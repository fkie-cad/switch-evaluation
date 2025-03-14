from __future__ import annotations

import base64
import json
import multiprocessing
import re
import subprocess
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, Optional, List, Tuple

import tqdm

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

C_LANGUAGE = Language(tsc.language())

def list_replace(replacee: List[str], replacement: List[str], replacement_list: List[str]) -> List[str]:
    """Replace each occurrence of the sublist replacee by the sublist replacement."""
    new_list: List = []
    idx = 0
    while idx < len(replacement_list):
        if idx + len(replacee) <= len(replacement_list) and replacement_list[idx : idx + len(replacee)] == replacee:
            new_list += replacement
            idx += len(replacee)
        else:
            new_list.append(replacement_list[idx])
            idx += 1
    return new_list


class SwitchInformationParser:
    """Class in charge of parsing all switch-information."""

    def __init__(self, path: Path, gcc="gcc-14"):
        self.filepath = path
        self._gcc = gcc

    def count_switches_in_file(self):
        """Generate new json file with switch-information."""
        with open(self.filepath, "r") as infile:
            lines = list(infile.readlines())
        with open(self.filepath.with_stem(self.filepath.stem + "_switches"), "w") as outfile:
            with multiprocessing.Pool(multiprocessing.cpu_count()) as pool:
                for result in tqdm.tqdm(pool.imap(self._handle_line, lines), total=len(lines)):
                    if result:
                        json.dump(result, outfile)
                        outfile.write("\n")
                        outfile.flush()

    def _handle_line(self, line: str) -> Optional[Dict]:
        """Compute switch-information for the function in the given line."""
        data = json.loads(line)

        if source_code := base64.standard_b64decode(data["decompiler_output"]).decode("ascii"):
            source_code_wo_comments = self._remove_comments_from_source(source_code)
            if (switch_data := self._parse_switches_in(source_code_wo_comments)) is not None:
                data["switches"] = switch_data
                del data["decompiler_output"]
                return data
        else:
            print("Source code is empty")

    def _remove_comments_from_source(self, source_code: str):
        """Remove comments from the given source-code."""
        with NamedTemporaryFile(mode="w+", suffix=".c") as tmpfile:
            tmpfile.write(source_code)
            tmpfile.flush()
            result = subprocess.run(
                [f"{self._gcc}", "-fpreprocessed", "-dD", "-E", tmpfile.name], shell=False, capture_output=True, text=True
            )
            if result.returncode != 0:
                print(f"Failed to remove comments from function ({result.stderr.strip()})")
                return source_code
            return "\n".join(l.strip() for l in result.stdout.split("\n") if l and not l.startswith("#"))

    def _parse_switches_in(self, original_source: str) -> Optional[List]:
        """Parse the switches in the source-code and return the data"""
        result = []
        parser = Parser(C_LANGUAGE)
        tree = parser.parse(original_source.encode("utf8"))

        def walk_tree(node):
            if node.type == 'switch_statement':
                case_constants = []
                switch_indicator_node = node.children[0]
                switch_expression_node = node.children[1]
                switch_expression = original_source.encode("utf8")[switch_expression_node.start_byte:switch_expression_node.end_byte].decode("utf-8").strip()
                while switch_expression[0] == "(" and switch_expression[-1] == ")":
                    switch_expression = switch_expression[1:-1].strip()
                switch_case_compound_node = node.children[2]

                # Make sure the we are interpreting the way that tree-sitter parses switch statements correctly
                assert len(node.children) == 3
                assert switch_indicator_node.type == "switch"
                assert switch_expression_node.type == "parenthesized_expression"
                assert switch_case_compound_node.type == "compound_statement"

                for case_node in switch_case_compound_node.children:
                    if case_node.type == 'case_statement':
                        constant_node = case_node.child_by_field_name('value')
                        if constant_node == None:
                            # This is a default case. *However*: We only count it if it does not contain a goto or "JUMPOUT" (as produced by Ghidra)
                            default_code = original_source.encode("utf8")[case_node.start_byte:case_node.end_byte].decode("utf-8")
                            if all(keyword not in default_code for keyword in ["goto", "JUMPTOUT", "abort()", "LAB_", "LABEL_"]):
                                case_constants.append("default")
                        else:
                            case_code = original_source.encode("utf8")[case_node.start_byte:case_node.end_byte].decode("utf-8")
                            case_constant = original_source.encode("utf8")[constant_node.start_byte:constant_node.end_byte].decode("utf-8")
                            try:
                                # We prefer decimal values over hex values. By this normalization, we ease the normalization etc.
                                case_constant = int(case_constant.strip(), 0)
                            except: pass

                            # We also do not count cases that contain a goto, a goto-label or a JUMPOUT
                            if any(keyword in case_code for keyword in ["goto", "JUMPTOUT", "abort()", "LAB_", "LABEL_"]):
                                continue

                            # We do not count cases that solely contain a break
                            if "".join(line.strip() for line in case_code.split("\n")) == f"case {case_constant}:break;":
                                continue

                            case_constants.append(f"case {case_constant}")

                if case_constants: result.append({f"switch ({switch_expression})": case_constants})

            for child in node.children:
                walk_tree(child)

        walk_tree(tree.root_node)
        return result
        
if __name__ == "__main__":
    for json_path in [
        Path("202X-XX-XX-ghidra.json"),
        Path("202X-XX-XX-dewolf.json"),
        Path("202X-XX-XX-ida.json")
    ]:
        SwitchInformationParser(json_path).count_switches_in_file()
