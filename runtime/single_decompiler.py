from __future__ import annotations
import datetime
import json
import sys
from pathlib import Path

import typer

DEWOLF_PATH = Path("dewolf")
TMP_BINJA_DB_FILE = "tmp.bndb"

sys.path.extend([str(DEWOLF_PATH)])
from decompile import Decompiler


def decompile_single_function(decompiler, function_name):
    start_time = datetime.datetime.now()
    _ , code = decompile_function(decompiler, function_name)
    end_time = datetime.datetime.now()
    return json.dumps({
        "decompiler_output": code,
        "function_name": function_name,
        "time": str((end_time - start_time).total_seconds()),
    })


def decompile_function(decompiler, function_name):
    return decompiler.decompile(function_name)


def main(function_name: str = typer.Argument(help="Name of function we want to decompile.")):
    """This program takes a program, i.e., python or c, and creates a png containing the highlighted code using minted."""
    decompiler = Decompiler.from_path(TMP_BINJA_DB_FILE)
    print(decompile_single_function(decompiler, function_name))


if __name__ == "__main__":
    typer.run(main)
