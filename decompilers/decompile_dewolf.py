import subprocess
import os
import json
import base64
import datetime
import sys
import hashlib
import errno
import os
import signal
import functools
import time
import multiprocessing
import git

from pebble import ProcessPool
from concurrent.futures import TimeoutError

DEWOLF_PATH = "dewolf"
OUTPUT_FILE = datetime.datetime.now().strftime("%Y-%m-%d") + "-dewolf.json"
TMP_BINJA_DB_FILE = ".tmp.bndb"
TIMEOUT_SECONDS = 5 * 60

repo = git.Repo(DEWOLF_PATH)
DEWOLF_VERSION = repo.head.object.hexsha

sys.path.append(DEWOLF_PATH)
from decompile import Decompiler


def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


def decompile_all_files_in_directory(directory):
    if os.path.exists(OUTPUT_FILE): os.remove(OUTPUT_FILE)
    for subdir, _, files in os.walk(directory):
        for file in sorted(files):
            if file == ".DS_Store": continue
            decompile_all_functions_in_binary(os.path.join(subdir, file))


def decompile_all_functions_in_binary(path):
    print(f"[*] Disassembling {path}")
    sha256 = sha256sum(path)
    decompiler = Decompiler.from_path(path)
    decompiler._frontend._bv.create_database(TMP_BINJA_DB_FILE, None)
    all_functions = list(decompiler._frontend.get_all_function_names())
    with ProcessPool() as pool:
        iterator = pool.map(decompile_single_function, all_functions, timeout=TIMEOUT_SECONDS).result()
        with open(OUTPUT_FILE, "a") as outfile:
            while True:
                try:
                    result = next(iterator)
                    dewolf_output = result["decompiler_output"].encode('utf-8')
                    print(f"[**] Finished Decompiling {result['function_name']}")
                    assert base64.standard_b64decode(base64.standard_b64encode(dewolf_output)) == dewolf_output
                    json.dump({
                        "decompiler": "dewolf",
                        "decompiler_version": DEWOLF_VERSION,
                        "error": "Failed to decompile" in result["decompiler_output"],
                        "binary_name": path.replace(os.path.dirname(os.path.abspath(__file__)), ""),
                        "binary_sha256": sha256,
                        "function_name": result["function_name"],
                        "decompiler_output": base64.standard_b64encode(dewolf_output).decode("ascii"),
                        }, outfile)
                    outfile.write("\n")
                    outfile.flush()
                except StopIteration:
                    break
                except TimeoutError as error:
                    pass

def decompile_single_function(function_name):
    print(f"[**] Started Decompiling {function_name}")
    decompiler = Decompiler.from_path(TMP_BINJA_DB_FILE)
    decompiler_task = decompile_function(decompiler, function_name)
    return {
        "decompiler_output": decompiler_task.code,
        "function_name": function_name
    }
    

def decompile_function(decompiler, function_name):
    return decompiler.decompile(function_name)     

if __name__ == "__main__":
    decompile_all_files_in_directory("dataset")
