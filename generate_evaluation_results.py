from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, asdict, is_dataclass
from itertools import combinations, product, chain, permutations
from pathlib import Path
from typing import List, Dict, Tuple, Iterator, Optional, Union, Set, DefaultDict
from networkx import Graph, max_weight_matching


def clean_constant(case_constant: str):
    case_constant = case_constant.removeprefix("(char *)")
    old_constant = ""
    while case_constant != old_constant:
        old_constant = case_constant
        case_constant = case_constant.removesuffix("u")
        case_constant = case_constant.removesuffix("L")
    if "\\\\" in case_constant:
        case_constant = case_constant.replace("\\\\", "\\")

    # Try to normalize hex constants
    try:
        # print(case_constant)
        case_constant = str(int(case_constant, 0))
    except: pass

    # Try to normalize case constants in ascii range often represented as chars
    try:
        if int(case_constant, 0) > 0 and int(case_constant, 0) <= 0xff:
            case_constant = chr(int(case_constant, 0))
    except: pass

    case_constant = case_constant.strip("'").strip('"')

    return case_constant


def get_sorted_constants(cases: List[str]) -> List[str]:
    result = list()
    for case in cases:
        if "default" in case:
            continue
        case_constant = case.removeprefix("case ")
        case_constant = clean_constant(case_constant)
        result.append(case_constant)
    return sorted(result)


def switch_similarity(switch_data1: SwitchData, switch_data2: SwitchData) -> float:
    constants1 = set(switch_data1.case_constants)
    constants2 = set(switch_data2.case_constants)
    if constants1 == constants2:
        return 1
    if constants1.issubset(constants2) or constants2.issubset(constants1):
        common_constants = constants1 & constants2
        return 0.5 * (len(common_constants) / len(constants1) + len(common_constants) / len(constants2)) + 0.0001
    if all(isinstance(c, int) for c in constants1 | constants2):
        possible_shifts = set(x - y for x, y in product(constants1, constants2))
        common_cases = 0
        for shift in possible_shifts:
            common_cases = max(sum(y + shift in constants1 for y in constants2), common_cases)
    else:
        # print("Some strings in the cases that could not be resolved")
        common_cases = sum(case in constants1 for case in constants2)
    return 0.5 * (common_cases / len(constants1) + common_cases / len(constants2)) + (
        0.0001 if len(constants1 & constants2) == common_cases else 0
    )


def str_to_int(value: str) -> Union[int, str]:
    try:
        return int(value, 0)
    except ValueError:
        pass
    if value[0] == value[-1] == "'":
        try:
            return ord(value[1:-1])
        except TypeError:
            pass
    return value


@dataclass(frozen=True)
class FunctionIdentifier:
    sha256: str
    name: str

    def __str__(self) -> str:
        return f"{self.sha256} {self.name}"


@dataclass(frozen=True)
class DecompilerData:
    decompiler: str
    decompiler_version: str


@dataclass(frozen=True)
class SwitchData:
    switch_expression: str
    has_default: bool
    case_constants: List[str]
    # number_of_cases: int

    @property
    def number_of_cases(self) -> int:
        return len(self.case_constants)

    @classmethod
    def generate_from(cls, switches: List[Dict[str, List[str]]]) -> List[SwitchData]:
        result = list()
        for switches_dict in switches:
            for switch_name, cases in switches_dict.items():
                # result.append(SwitchData(switch_name, "default" in cases, len(cases)))
                case_constant = get_sorted_constants(cases)
                result.append(SwitchData(switch_name, "default" in cases, case_constant))
        return result


@dataclass(frozen=True)
class EnhancedSwitchData(SwitchData):
    decompiler: str

    def __hash__(self) -> int:
        return id(self)

    @classmethod
    def from_switch_data(cls, switch_data: SwitchData, decompiler: str) -> EnhancedSwitchData:
        return cls(switch_data.switch_expression, switch_data.has_default, switch_data.case_constants, decompiler)


@dataclass(frozen=True)
class FunctionData:
    decompiler_data: DecompilerData
    switch_data: List[SwitchData]
    decompiler_error: bool = False


@dataclass(frozen=True)
class SameSwitch:
    switches: List[EnhancedSwitchData]

    def __str__(self):
        return "Matched:\n" + "\n".join(f"{switch.decompiler}: {switch.case_constants}: default: {switch.has_default}" for switch in self.switches)

    @property
    def dewolf(self) -> Optional[SwitchData]:
        return self.return_switch_for("dewolf")

    @property
    def ghidra(self) -> Optional[SwitchData]:
        return self.return_switch_for("ghidra")

    @property
    def ida(self) -> Optional[SwitchData]:
        return self.return_switch_for("ida")

    @property
    def is_similar_enough(self) -> bool:
        return all(switch_similarity(switches1, switches2) >= 0.8 for switches1, switches2 in combinations(self.switches, 2))

    def return_switch_for(self, decompiler: str):
        for switch in self.switches:
            if switch.decompiler == decompiler:
                return switch
        return None

    @classmethod
    def generate_one_match(cls, switches_of_decompiler: Dict[str, List[EnhancedSwitchData]]) -> SameSwitch:
        assert all(len(switch_data) == 1 for switch_data in switches_of_decompiler.values()), "Each decompiler has at most one switch!"
        return cls(list(chain(*switches_of_decompiler.values())))

    @classmethod
    def generate_single_matches(cls, switches_of_decompiler: Dict[str, List[EnhancedSwitchData]]) -> Iterator[SameSwitch]:
        """The given switches"""
        assert len(switches_of_decompiler) == 1, "Only one decompiler should have a switch!"
        decompiler = list(switches_of_decompiler.keys())[0]
        for switch in switches_of_decompiler[decompiler]:
            yield cls([switch])


class SimilarityHandler:
    def __init__(self, switches_of_decompiler: Dict[str, List[EnhancedSwitchData]], graph: Graph):
        self.switches_of_decompiler: Dict[str, List[EnhancedSwitchData]] = switches_of_decompiler
        self.similarity_graph: Graph = graph
        self._working_graph: Graph = graph
        self.sorted_decompilers = sorted(self.switches_of_decompiler, key=lambda k: len(self.switches_of_decompiler[k]))

    @classmethod
    def generate(cls, switches_of_decompiler: Dict[str, List[EnhancedSwitchData]]):
        graph = Graph()
        graph.add_nodes_from(chain(*switches_of_decompiler.values()))
        for decompiler1, decompiler2 in combinations(switches_of_decompiler, 2):
            for switch_data_1, switch_data_2 in product(switches_of_decompiler[decompiler1], switches_of_decompiler[decompiler2]):
                assert switch_data_1 in graph and switch_data_2 in graph and (switch_data_1, switch_data_2) not in graph.edges
                graph.add_edge(switch_data_1, switch_data_2, similarity=switch_similarity(switch_data_1, switch_data_2))
        return cls(switches_of_decompiler, graph)

    def get_similarity_between(self, switch1: EnhancedSwitchData, switch2: EnhancedSwitchData) -> Optional[int]:
        if self.similarity_graph.has_edge(switch1, switch2):
            return self.similarity_graph[switch1][switch2]["similarity"]
        return None

    def group_switches(self):
        match len(self.switches_of_decompiler):
            case 2:
                yield from self._group_for_two_decompilers()
            case 3:
                yield from self._group_for_three_decompilers()
            case _:
                raise ValueError("We match switches of 2 or 3 decompilers!")

    def _group_for_two_decompilers(self) -> Iterator[SameSwitch]:
        matching = self.__get_matching_of(self._working_graph)
        for node in self.switches_of_decompiler[self.sorted_decompilers[-2]]:
            if node not in self._working_graph:
                continue
            self._is_best_possible_match(node, matching[node])
            yield SameSwitch([node, matching[node]])
        for node in self.switches_of_decompiler[self.sorted_decompilers[-1]]:
            if node not in self._working_graph:
                continue
            if node not in matching:
                yield SameSwitch([node])

    def _group_for_three_decompilers(self) -> Iterator[SameSwitch]:
        subgraph = self.similarity_graph.subgraph(
            self.switches_of_decompiler[self.sorted_decompilers[1]] + self.switches_of_decompiler[self.sorted_decompilers[2]]
        )
        matching_1 = self.__get_matching_of(subgraph)
        subgraph = self.similarity_graph.subgraph(
            self.switches_of_decompiler[self.sorted_decompilers[0]] + self.switches_of_decompiler[self.sorted_decompilers[2]]
        )
        matching_2 = self.__get_matching_of(subgraph)
        for node in self.switches_of_decompiler[self.sorted_decompilers[2]]:
            same_switch = [node]
            if node in matching_1:
                self._is_best_possible_match(node, matching_1[node])
                same_switch.append(matching_1[node])
            if node in matching_2:
                self._is_best_possible_match(node, matching_2[node])
                same_switch.append(matching_2[node])
            if node in matching_1 and node in matching_2:
                self._is_best_possible_match(matching_1[node], matching_2[node])
            yield SameSwitch(same_switch)

    @staticmethod
    def __get_matching_of(graph: Graph) -> Dict[EnhancedSwitchData, EnhancedSwitchData]:
        matching_edges: Set[Tuple[EnhancedSwitchData, EnhancedSwitchData]] = max_weight_matching(
            graph, maxcardinality=True, weight="similarity"
        )
        return {e[i]: e[j] for e in matching_edges for i, j in [(0, 1), (1, 0)]}

    def _is_best_possible_match(self, node1: EnhancedSwitchData, node2: EnhancedSwitchData):
        """Check whether the switches are matched to best option, otherwise it prints a warning."""
        matched_similarity = self.get_similarity_between(node1, node2)
        if any(
            self.get_similarity_between(node1, neighbour) > matched_similarity
            for neighbour in self.similarity_graph.neighbors(node1)
            if neighbour.decompiler == node2.decompiler
        ) or any(
            self.get_similarity_between(node2, neighbour) > matched_similarity
            for neighbour in self.similarity_graph.neighbors(node2)
            if neighbour.decompiler == node1.decompiler
        ):
            print(f"This may not be the perfect match: {node1} and {node2}")


def load_file(filepath: Path) -> Dict[FunctionIdentifier, FunctionData]:
    """Load and processes the switch-data of the given file."""
    result: Dict[FunctionIdentifier, FunctionData] = dict()
    with open(filepath, "r") as infile:
        for line in infile.readlines():
            data = json.loads(line)
            if not data:
                continue
            function_identifier = FunctionIdentifier(data["binary_sha256"], data["function_name"])
            decompiler_data = DecompilerData(data["decompiler"], str(data["decompiler_version"]))
            switch_data: List[SwitchData] = SwitchData.generate_from(data["switches"])
            decompiler_error = True if "error" in data and data["error"] else False
            result[function_identifier] = FunctionData(decompiler_data, switch_data, decompiler_error)
            if any(len(switch.case_constants) != len(set(switch.case_constants)) for switch in switch_data):
                print(
                    f"=== Have a look at decompiler output of {decompiler_data.decompiler} file {function_identifier}: Two case-constants have same value"
                )
    return result


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, data_object):
        if is_dataclass(data_object):
            return asdict(data_object)
        return super().default(data_object)


class DataProcessor:
    def __init__(self, output_path: Path = Path("output.json")):
        input_files: Dict[str, Path] = {
            "dewolf": Path("202X-XX-XX-dewolf_switches.json"),
            "ghidra": Path("202X-XX-XX-ghidra_switches.json"),
            "ida":    Path("202X-XX-XX-ida_switches.json"),
        }
        self._output_path = output_path
        self._switch_data_of: Dict[str, Dict[FunctionIdentifier, FunctionData]] = {
            decompiler: load_file(file) for decompiler, file in input_files.items()
        }
        self._result: Dict[FunctionIdentifier, List[FunctionData]] = dict()

    def process(self):
        """Process collected switch-data."""
        total_count = 0
        for function_identifier in self._switch_data_of["dewolf"]:
            if self._not_all_decompilers_decompiled(function_identifier):
                total_count += 1
                continue
            if self._non_decompiler_output_contains_switch(function_identifier): continue
            self._result[function_identifier] = [d[function_identifier] for d in self._switch_data_of.values()]
        print(f"Considering a total of {total_count} functions that have been decompiled by every decompiler")
        self._remove_duplicates()
        with open(output_path, "w") as outfile:
            json.dump({str(f_id): data for f_id, data in self._result.items()}, outfile, cls=EnhancedJSONEncoder, indent=2)

    def _not_all_decompilers_decompiled(self, function_identifier: FunctionIdentifier) -> bool:
        if self._switch_data_of["dewolf"][function_identifier].decompiler_error:
            # print(f"Dewolf did not decompile the sample {function_identifier} correctly")
            return True
        return not all(function_identifier in decompiled_functions for decompiled_functions in self._switch_data_of.values())

    def _non_decompiler_output_contains_switch(self, function_identifier: FunctionIdentifier) -> bool:
        return not any(function_data_of[function_identifier].switch_data for function_data_of in self._switch_data_of.values())

    def _remove_duplicates(self):
        """
        Remove function duplication.
        -> Functions with the same name and same occurrence of switches for all decompilers.
        """

        def get_switch_data_of(decompilers_function_data: List[FunctionData]) -> Tuple[Tuple[str, Tuple[Tuple[int, bool]]]]:
            """Return the switch_data for the given function-data."""
            simplified_data: List[Tuple[str, Tuple[Tuple[int, bool]]]] = list()
            for function_data in decompilers_function_data:
                switch_data: Tuple[Tuple[Tuple, bool]] = tuple(
                    sorted((switch.switch_expression, tuple(sorted(switch.case_constants)), switch.has_default) for switch in function_data.switch_data)
                )
                simplified_data.append((function_data.decompiler_data.decompiler, switch_data))
            return tuple(sorted(simplified_data))

        already_collected_functions = set()
        for function_identifier, decompilers_function_data in list(self._result.items()):
            switch_data_of_function = get_switch_data_of(decompilers_function_data)
            if (function_identifier.name, switch_data_of_function) in already_collected_functions:
                # if(switch_data_of_function): print(switch_data_of_function)
                del self._result[function_identifier]
            else:
                already_collected_functions.add((function_identifier.name, switch_data_of_function))

    def render_results(self):
        print(
            json.dumps(
                {
                    "num_switches_total_decompiled_all_raw": self.__get_total_number_of_switches(),
                    "num_cases_total_decompiled_all_raw": self.__get_total_number_of_cases(),
                    # "num_switches_total_decompiled_all_filtered": self._get_total_number_of_switches_filtered(),
                    # "num_cases_total_decompiled_all_raw_filtered": self.__get_total_number_of_cases_filtered(),
                    # "num_defaults_decompiled_all_raw_filtered": self.__get_total_number_of_defaults_filtered(),
                    "num_defaults_decompiled_all_raw": self.__get_total_number_of_defaults(),
                },
                indent=4,
                sort_keys=True,
            )
        )

    def render_switch_table(self, only_switches_decompiled_by_all=True):
        same_switch_data: Dict[FunctionIdentifier, List[SameSwitch]] = dict(self._group_switches())
        switches_detected_by: DefaultDict[Tuple[str], int] = defaultdict(int)  # all tuples
        # Tuple: count (d1 switches without d2 switches), (cases d1 has that d2 does not have), (cases d1 has that d2 does not have if both found switch)
        # (how often more cases) (defaults d1 has that d2 does not have), (defaults d1 has that d2 does not have if both found switch)
        decompiler_comparison: Dict[str, Dict[str, List[int, int, int]]] = {
            d1: {d2: [0, 0, 0, 0, 0, 0, 0] for d2 in self._switch_data_of if d1 != d2} for d1 in self._switch_data_of
        }
        decompiler_against_others = {decompiler: {
                "unique_switches": 0,
                "non_unique_switches": 0,
                "unique_defaults": 0,
                "non_unique_defaults": 0,
                "unique_cases": 0,
                "non_unique_cases": 0
            } for decompiler in list(self._switch_data_of) + ["_sum"]} 
        for function, matched_switches in same_switch_data.items():
            # print(f"Function {function}")
            for same_switch in matched_switches:
                decompilers = tuple(sorted(switch.decompiler for switch in same_switch.switches))
                switches_detected_by[decompilers] += 1
                for d1, d2 in permutations(self._switch_data_of, 2):
                    if (switch1 := same_switch.return_switch_for(d1)) is None:
                        continue
                    if (switch2 := same_switch.return_switch_for(d2)) is None:
                        decompiler_comparison[d1][d2][0] += 1
                        decompiler_comparison[d1][d2][1] += len(switch1.case_constants)
                        decompiler_comparison[d1][d2][3] += 1
                        decompiler_comparison[d1][d2][5] += switch1.has_default
                    else:
                        decompiler_comparison[d1][d2][1] += max(0, len(switch1.case_constants) - len(switch2.case_constants))
                        decompiler_comparison[d1][d2][2] += max(0, len(switch1.case_constants) - len(switch2.case_constants))
                        decompiler_comparison[d1][d2][3] += len(switch1.case_constants) > len(switch2.case_constants)
                        decompiler_comparison[d1][d2][4] += len(switch1.case_constants) > len(switch2.case_constants)
                        decompiler_comparison[d1][d2][5] += switch1.has_default and not switch2.has_default
                        decompiler_comparison[d1][d2][6] += switch1.has_default and not switch2.has_default

                def filtered_cases(case_constants_list):
                    # Filter any all caps strings with underscores such as TYPE_UINT
                    # While this hinders the exact matching of each case (which we do not need for evaluation), it fixes the total case numbers    
                    return set(cc for cc in case_constants_list if not re.search(r"[A-Z_]{3,}", cc))
                def filtered_cases_neg(given_switch):
                    if given_switch is None: return set()
                    return set(cc for cc in given_switch.case_constants if re.search(r"[A-Z_]{3,}", cc))

                def unique_cases_in_current_switch():
                    return filtered_cases(set(
                        case_constant
                        for case_constant in sum((same_switch.return_switch_for(decompiler).case_constants for decompiler in self._switch_data_of if same_switch.return_switch_for(decompiler)), [])
                    ))
                
                def cases_in_current_switch_matched_by_other_decompilers(other_decompilers):
                    return set(
                        case_constant
                        for case_constant in sum((same_switch.return_switch_for(decompiler).case_constants for decompiler in other_decompilers if same_switch.return_switch_for(decompiler)), [])
                    )

                decompiler_against_others["_sum"]["unique_switches"] += 1

                # only count for switches that have been recovered by all decompilers
                if only_switches_decompiled_by_all and any(same_switch.return_switch_for(decompiler) is None for decompiler in self._switch_data_of): continue
                
                decompiler_against_others["_sum"]["unique_cases"] += len(unique_cases_in_current_switch())
                decompiler_against_others["_sum"]["unique_defaults"] += 1 if any(same_switch.return_switch_for(decompiler).has_default for decompiler in self._switch_data_of if same_switch.return_switch_for(decompiler)) else 0

                # print("*"*50)
                # print(f"_sum: {len(unique_cases_in_current_switch())}")
                for decompiler in self._switch_data_of:
                    other_decompilers = list(set(self._switch_data_of) - set([decompiler]))
                    recovered_switch = same_switch.return_switch_for(decompiler)
                    if recovered_switch is None: continue

                    # print(f"{decompiler}:{sorted(recovered_switch.case_constants)}")

                    recovered_switch_other_one = same_switch.return_switch_for(other_decompilers[0])
                    recovered_switch_other_two = same_switch.return_switch_for(other_decompilers[1])
                    if recovered_switch_other_one is None and recovered_switch_other_two is None:
                        decompiler_against_others[decompiler]["unique_switches"] += 1
                    else:
                        decompiler_against_others[decompiler]["non_unique_switches"] += 1

                    # Unique cases are those that have not been recovered by any other decompilers
                    num_unique_cases = len(set(filtered_cases(recovered_switch.case_constants)) - cases_in_current_switch_matched_by_other_decompilers(other_decompilers))

                    # substract the number of filtered cases from other decompilers because those are cases that other decompilers potentially have also recovered
                    if filtered_cases_other_decompilers := len(filtered_cases_neg(recovered_switch_other_one) | filtered_cases_neg(recovered_switch_other_two)):
                        # if the decompiler itself also discovered cases that have been filtered already, the number of unique cases does not need to be reduced any more than the additional cases
                        num_unique_cases = max(0, num_unique_cases - filtered_cases_other_decompilers + len(filtered_cases_neg(recovered_switch)))

                    # print(f"{decompiler} unique: {num_unique_cases}")

                    decompiler_against_others[decompiler]["unique_cases"] += num_unique_cases

                    if recovered_switch.has_default:
                        num_non_unique_cases = len(unique_cases_in_current_switch()) - num_unique_cases
                    else:
                        num_non_unique_cases = len(set(recovered_switch.case_constants)) - num_unique_cases
                        
                    decompiler_against_others[decompiler]["non_unique_cases"] += num_non_unique_cases

                    # print switches where dewolf has no default but others do
                    # The following functions have the default outside the switch and are still counted:
                    # 0fc28e1b824954b39d6cb44c86dd21f5e2851b0b2ae852a0a45be99700d063bf unary_operator (default function call right after switch)
                    # 0fc28e1b824954b39d6cb44c86dd21f5e2851b0b2ae852a0a45be99700d063bf printf_fetchargs (return right after switch)
                    # 82fe7b976a515705639e485ae7155c18dbff2112a15703cfdecdbbed0aff5c2c hextobin (return in default, comes after switch in dewolf)
                    # NOT ef94f6bb03a4a56c5231ec5a3998334775bcf9bd0402f5c301b0de132c4b3cd5 eval2 (this one is questionable)
                    # 398552571c0e9c13d068b96cf8345636319181041b45655816637a55385fdd6d parse_field_count (return in default, comes after switch in dewolf)
                    # 5c4104ae31b302c7ec6782518e8f327f737e657ba8bc86822e47e5486c3826ac is_char_class_member (return in default, comes after switch in dewolf)
                    if (recovered_switch_other_one is not None and recovered_switch_other_one.has_default) or (recovered_switch_other_two is not None and recovered_switch_other_two.has_default):
                        if decompiler == "dewolf" and not recovered_switch.has_default: print("dewolf no default", function)

                    if recovered_switch.has_default:
                        if (recovered_switch_other_one is not None and recovered_switch_other_one.has_default) or (recovered_switch_other_two is not None and recovered_switch_other_two.has_default):
                            decompiler_against_others[decompiler]["non_unique_defaults"] += 1    
                        else:
                            decompiler_against_others[decompiler]["unique_defaults"] += 1        

                
                # print(same_switch)
                # self.__check_similarity(same_switch, function)
        print("\n ====Results=====\n")
        print("Venn Diagram:\n")
        for decompilers, switch_count in switches_detected_by.items():
            print(f"Common Switches of decompilers {decompilers}: {switch_count}")
        print("\nComparision:")
        for d1, d2 in permutations(self._switch_data_of, 2):
            data = decompiler_comparison[d1][d2]
            print(f"\ndecompiler {d1} over {d2}:")
            print(f"more switches: {data[0]}")
            print(f"more cases: {data[1]}")
            print(f"more cases (only if both have a switch): {data[2]}")
            print(f"switches with more cases: {data[3]}")
            print(f"switches with more cases (only if both have a switch): {data[4]}")
            print(f"more defaults: {data[5]}")
            print(f"more defaults (only if both have a switch): {data[6]}")

        print(json.dumps(decompiler_against_others, sort_keys=True, indent=4))

    def _group_switches(self) -> Iterator[Tuple[FunctionIdentifier, List[SameSwitch]]]:
        for function, decompilers in self._result.items():
            switches_of_decompiler: Dict[str, List[EnhancedSwitchData]] = {
                decompiler.decompiler_data.decompiler: list(
                    EnhancedSwitchData.from_switch_data(switch, decompiler.decompiler_data.decompiler)
                    for switch in self.__get_filtered_switches(decompiler.switch_data)
                )
                for decompiler in decompilers
                if decompiler.switch_data
            }
            if all(len(switch_data) == 0 for switch_data in switches_of_decompiler.values()):
                continue
            if len(switches_of_decompiler) == 1:
                matched_switches = list(SameSwitch.generate_single_matches(switches_of_decompiler))
            elif all(len(switch_list) == 1 for switch_list in switches_of_decompiler.values()):
                same_switch = SameSwitch.generate_one_match(switches_of_decompiler)
                self.__check_similarity(same_switch, function)
                matched_switches = [same_switch]
            else:
                # We assume that either no decompiler has two times the exact same switch
                # or only one decompiler has two times the same and all others have only one switch.
                assert (
                    all(len(set(switch_data)) == len(switch_data) for switch_data in switches_of_decompiler.values())
                    or sum(len(switch_data) > 1 for switch_data in switches_of_decompiler.values()) == 1
                ), "We have to think about how to match these cases!"
                # At least two decompilers and one has at least two switches
                assert len(switches_of_decompiler) > 1 and any(
                    len(switch_data) > 1 for switch_data in switches_of_decompiler.values()
                ), "We have at least two decompilers and at least one has more than one switch."
                similarity_handler = SimilarityHandler.generate(switches_of_decompiler)
                matched_switches = list()
                for same_switch in similarity_handler.group_switches():
                    # self.__check_similarity(same_switch, function)
                    matched_switches.append(same_switch)
            yield function, matched_switches

    @staticmethod
    def __check_similarity(same_switch: SameSwitch, function: FunctionIdentifier):
        if not same_switch.is_similar_enough:
            print(f"Check whether switches of function {function} are really the same:")
            # print("\n".join(str(switch[0]) for switch in switches_of_decompiler.values()))

    @staticmethod
    def __get_filtered_switches(switch_data: List[SwitchData]) -> Iterator[SwitchData]:
        for switch in switch_data:
            if "exit_" not in switch.switch_expression and "entry_" not in switch.switch_expression:
                yield switch

    def __get_total_number_of_switches(self) -> Dict[str, int]:
        switches_of_decompiler: Dict[str, int] = {decompiler_name: 0 for decompiler_name in self._switch_data_of}
        for decompilers_function_data in self._result.values():
            for function_data in decompilers_function_data:
                switches_of_decompiler[function_data.decompiler_data.decompiler] += len(function_data.switch_data)

        return switches_of_decompiler

    def _get_total_number_of_switches_filtered(self):
        switches_of_decompiler: Dict[str, int] = {decompiler_name: 0 for decompiler_name in self._switch_data_of}
        for decompilers_function_data in self._result.values():
            for function_data in decompilers_function_data:
                switches_of_decompiler[function_data.decompiler_data.decompiler] += sum(
                    1 for _ in self.__get_filtered_switches(function_data.switch_data)
                )

        return switches_of_decompiler

    def __get_total_number_of_cases(self):
        total_number_of_cases_of_decompiler: Dict[str, int] = {decompiler_name: 0 for decompiler_name in self._switch_data_of}
        for decompilers_function_data in self._result.values():
            for function_data in decompilers_function_data:
                total_number_of_cases_of_decompiler[function_data.decompiler_data.decompiler] += sum(
                    switch.number_of_cases for switch in function_data.switch_data
                )

        return total_number_of_cases_of_decompiler

    def __get_total_number_of_cases_filtered(self):
        total_number_of_cases_of_decompiler: Dict[str, int] = {decompiler_name: 0 for decompiler_name in self._switch_data_of}
        for decompilers_function_data in self._result.values():
            for function_data in decompilers_function_data:
                total_number_of_cases_of_decompiler[function_data.decompiler_data.decompiler] += sum(
                    switch.number_of_cases for switch in self.__get_filtered_switches(function_data.switch_data)
                )

        return total_number_of_cases_of_decompiler

    def __get_total_number_of_defaults_filtered(self):
        total_number_of_defaults_of_decompiler: Dict[str, int] = {decompiler_name: 0 for decompiler_name in self._switch_data_of}
        for decompilers_function_data in self._result.values():
            for function_data in decompilers_function_data:
                total_number_of_defaults_of_decompiler[function_data.decompiler_data.decompiler] += sum(
                    1 for switch in self.__get_filtered_switches(function_data.switch_data) if switch.has_default
                )

        return total_number_of_defaults_of_decompiler
    
    def __get_total_number_of_defaults(self):
        total_number_of_defaults_of_decompiler: Dict[str, int] = {decompiler_name: 0 for decompiler_name in self._switch_data_of}
        for decompilers_function_data in self._result.values():
            for function_data in decompilers_function_data:
                total_number_of_defaults_of_decompiler[function_data.decompiler_data.decompiler] += sum(
                    1 for switch in function_data.switch_data if switch.has_default
                )

        return total_number_of_defaults_of_decompiler


if __name__ == "__main__":
    output_path = Path("results.json")
    data_processor = DataProcessor(output_path)
    data_processor.process()
    data_processor.render_results()
    data_processor.render_switch_table()
