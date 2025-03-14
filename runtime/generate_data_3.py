import base64
import datetime
import hashlib
import json
import subprocess
import sys
import time
from itertools import islice
from multiprocessing import Process, cpu_count, Queue
from pathlib import Path
import signal

import git
from pebble import ProcessPool

DEWOLF_PATH =  Path("dewolf")
DATASET_PATH = Path("dataset")
OUTPUT_FILE = Path(datetime.datetime.now().strftime("%Y-%m-%d") + "-dewolf_main_coreutils_without_switch.json")
TMP_BINJA_DB_FILE = "tmp.bndb"
TIMEOUT_SECONDS = 5 * 60

repo = git.Repo(DEWOLF_PATH)
DEWOLF_VERSION = repo.head.object.hexsha
DEWOLF_BRANCH = repo.active_branch.name

sys.path.extend([str(DEWOLF_PATH)])
from decompile import Decompiler


class DecompilerInfo:
    sha256: str
    path: str


def sha256sum(filename):
    h = hashlib.sha256()
    b = bytearray(128 * 1024)
    mv = memoryview(b)
    with open(filename, "rb", buffering=0) as f:
        for n in iter(lambda: f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


def write_result(result, path, sha256):
    dewolf_output = result["decompiler_output"].encode("utf-8")
    assert base64.standard_b64decode(base64.standard_b64encode(dewolf_output)) == dewolf_output, "Assertion Failed"
    return {
        "branch": DEWOLF_BRANCH,
        "decompiler_version": DEWOLF_VERSION,
        "error": "Failed to decompile" in result["decompiler_output"] or result["time"] == "inf",
        "binary_name": path.name,
        "binary_sha256": sha256,
        "function_name": result["function_name"],
        "decompiler_output": base64.standard_b64encode(dewolf_output).decode("ascii"),
        "time": result["time"],
    }


def decompile_all_files_in_directory(directory: Path):
    count = 0
    if OUTPUT_FILE.is_file():
        OUTPUT_FILE.unlink()
    for file in sorted(directory.iterdir()):
        # if file.name < "uname":
        #     continue
        if count > 5:
            break
        decompile_all_functions_in_binary(file)
        count += 1


def decompile_all_functions_in_binary(path: Path):
    print(f"[*] Disassembling {path}")
    sha256 = sha256sum(path)
    decompiler = Decompiler.from_path(path)
    decompiler._frontend._bv.create_database(TMP_BINJA_DB_FILE, None)
    all_functions = decompiler._frontend.get_all_function_names()
    with ProcessPool() as pool:
        iterator = pool.map(decompile_single_function, all_functions).result()
        with open(OUTPUT_FILE, "a") as outfile:
            while True:
                try:
                    result = next(iterator)
                    json.dump(
                        write_result(result, path, sha256),
                        outfile,
                    )
                    outfile.write("\n")
                    outfile.flush()
                except StopIteration:
                    break


def decompile_single_function(function_name):
    print(f"[**] Started Decompiling {function_name}")
    try:
        subprocess_result = subprocess.run(
            f"python single_decompiler.py {function_name}", timeout=TIMEOUT_SECONDS + 10, capture_output=True, shell=True, check=True
        )
        print(f"[**] Finished Decompiling {function_name}")
        return json.loads(subprocess_result.stdout.decode("UTF-8"))
    except subprocess.TimeoutExpired:
        print(f"[**] Finished Decompiling {function_name} with timeout")
        return {
            "decompiler_output": "TimeOut",
            "function_name": function_name,
            "time": "inf",
        }
    except subprocess.SubprocessError:
        print(f"[**] Finished Decompiling {function_name} with Error")
        return {
            "decompiler_output": "Subprocess Error",
            "function_name": function_name,
            "time": "inf",
        }


if __name__ == "__main__":
    decompile_all_files_in_directory(DATASET_PATH)
