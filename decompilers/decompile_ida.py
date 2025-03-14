import datetime
import hashlib
import os
import json
import base64

from headless_ida import HeadlessIda


OUTPUT_FILE = datetime.datetime.now().strftime("%Y-%m-%d") + "-ida.json"


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
    sha256 = sha256sum(path)
    with open(OUTPUT_FILE, "a") as outfile:
        headlessida = HeadlessIda("INSERT_IDA_DIRECTORY_HERE/idat64", str(path))

        # Import IDA modules after initialization
        import idautils
        import ida_name
        import idaapi

        try:
            for func in idautils.Functions():
                function = idaapi.get_func(func)
                cfunc = idaapi.decompile(function)
                json.dump({
                    "decompiler": "ida",
                    "decompiler_version": "INSERT_VERSION_HERE",
                    "binary_sha256": sha256,
                    "binary_name": path.replace(os.path.dirname(os.path.abspath(__file__)), ""),
                    "function_name": ida_name.get_func_name(func),
                    "decompiler_output": base64.standard_b64encode( str(cfunc).encode("utf-8")).decode("ascii"),
                    }, outfile)
                outfile.write("\n")
                outfile.flush()
                
        except: pass


if __name__ == "__main__":
    decompile_all_files_in_directory("dataset")
