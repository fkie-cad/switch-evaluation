import subprocess
import os
import json
import base64
import datetime

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    current_ghidra_program = currentProgram
except: current_ghidra_program = None


GHIDRA_PATH = "ghidra"
GHIDRA_PROJECT_PATH = 'ghidra_headless_project'
OUTPUT_FILE = datetime.datetime.now().strftime("%Y-%m-%d") + "-ghidra.json"


def decompile_with_ghidra(binary_path):
    cmd = [
        GHIDRA_PATH + '/support/analyzeHeadless',
        GHIDRA_PROJECT_PATH,
        GHIDRA_PROJECT_PATH.split(os.sep)[-1],
        '-import',
        binary_path,
        '-postscript',
        os.path.join(os.path.dirname(os.path.abspath(__file__)),__file__),
        '-deleteProject'
    ]
    try:
        subprocess.run(' '.join(cmd), shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Error during decompilation:", e)
    except Exception as e:
        print("Unexpected error:", e)


def decompile_all_files_in_directory(directory):
    if os.path.exists(OUTPUT_FILE): os.remove(OUTPUT_FILE)
    for subdir, _, files in os.walk(directory):
        for file in files:
            print(file)
            decompile_with_ghidra(os.path.join(subdir, file))


def decompile_all_functions_in_program(program):
    for function in program.getFunctionManager().getFunctions(True):
        tokengrp = decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())
        try:
            yield function.name.strip(), tokengrp.getDecompiledFunction().getC().strip()
        except: pass


def save_all_decompiler_output_to_json(program):
    with open(OUTPUT_FILE, "a") as outfile:
        for n, c in decompile_all_functions_in_program(current_ghidra_program):
            assert base64.standard_b64decode(base64.standard_b64encode(c)) == c
            json.dump({
                "decompiler": "ghidra",
                "decompiler_version": getGhidraVersion(),
                "binary_name": program.getExecutablePath().lstrip(os.path.dirname(os.path.abspath(__file__))),
                "binary_sha256": program.getExecutableSHA256(),
                "function_name": n,
                "decompiler_output": base64.standard_b64encode(c),
                }, outfile)
            outfile.write("\n")
            outfile.flush()


if __name__ == "__main__" and current_ghidra_program is not None:
    decompinterface = DecompInterface()
    decompinterface.openProgram(current_ghidra_program);
    save_all_decompiler_output_to_json(current_ghidra_program)

elif __name__ == "__main__":
    decompile_all_files_in_directory("dataset")
    
