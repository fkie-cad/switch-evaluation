from __future__ import annotations

import base64
import json
from dataclasses import dataclass, is_dataclass, asdict
from pathlib import Path
from typing import Dict, Tuple, Literal, Union

import pandas as pd
import plotly.graph_objects as go
from numpy import log10, floor, ceil


DEWOLF_SWITCH =    Path("202X-XX-XX-dewolf_main_coreutils_switch.json")
DEWOLF_NO_SWITCH = Path("202X-XX-XX-dewolf_main_coreutils_without_switch.json")
OUTPUT_PATH =      Path("plot_data.csv")
FIGNAME = [Path("box_blot_slow_binaries"), Path("box_blot_fast_binaries"), Path("box_blot_in_between_binaries"), Path("box_blot_all_binaries")]


@dataclass(frozen=True)
class FunctionIdentifier:
    # sha256: str
    binary: str
    name: str

    def __str__(self) -> str:
        return f"{self.binary} {self.name}"


@dataclass(frozen=True)
class DecompilerOutput:
    _code: str
    has_error: bool
    time: Union[float, Literal["inf"]]
    branch: str
    decompiler_version: str

    @property
    def code(self) -> str:
        return base64.standard_b64decode(self._code).decode("ascii")


def load_file(filepath: Path) -> Dict[FunctionIdentifier, DecompilerOutput]:
    """Load and processes the switch-data of the given file."""
    result: Dict[FunctionIdentifier, DecompilerOutput] = dict()
    with open(filepath, "r") as infile:
        for line in infile.readlines():
            data = json.loads(line)
            if not data:
                continue
            function_identifier = FunctionIdentifier(data["binary_name"], data["function_name"])
            computation_time = data["time"] if data["time"] == "inf" else float(data["time"])
            decompiler_data = DecompilerOutput(
                data["decompiler_output"], data["error"], computation_time, data["branch"], data["decompiler_version"]
            )
            result[function_identifier] = decompiler_data
    return result


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, data_object):
        if is_dataclass(data_object):
            return asdict(data_object)
        return super().default(data_object)


class DataProcessor:
    def __init__(self):
        input_files: Dict[str, Path] = {
            "switch": DEWOLF_SWITCH,
            "no_switch": DEWOLF_NO_SWITCH,
        }
        self._decompiler_data_of: Dict[str, Dict[FunctionIdentifier, DecompilerOutput]] = {
            branch: load_file(file) for branch, file in input_files.items()
        }
        self._result: Dict[FunctionIdentifier, Tuple[DecompilerOutput, DecompilerOutput]] = dict()

    def process(self):
        """Process collected switch-data."""
        for function_identifier in self._decompiler_data_of["switch"]:
            if self._not_all_decompilers_decompiled(function_identifier):
                raise ValueError("This should not happen!")
                # continue

            self._result[function_identifier] = tuple(
                self._decompiler_data_of[branch][function_identifier] for branch in ["switch", "no_switch"]
            )
        # with open(OUTPUT_PATH, "w") as outfile:
        #     json.dump({str(f_id): data for f_id, data in self._result.items()}, outfile, cls=EnhancedJSONEncoder, indent=2)

    def _not_all_decompilers_decompiled(self, function_identifier: FunctionIdentifier) -> bool:
        return function_identifier not in self._decompiler_data_of["no_switch"]

    def render_results(self):
        if OUTPUT_PATH.is_file():
            OUTPUT_PATH.unlink()
        with open(OUTPUT_PATH, "a") as outfile:
            outfile.write("switch,no_switch")
            outfile.write("\n")
            outfile.flush()
            for function, (switch_data, no_switch_data) in self._result.items():
                if switch_data.has_error or no_switch_data.has_error:
                    continue
                switch_time = switch_data.time
                no_switch_time = no_switch_data.time
                outfile.write(f"{switch_time},{no_switch_time}")
                outfile.write("\n")
                outfile.flush()


def generate_plot():
    df = pd.read_csv(OUTPUT_PATH)
    print(len(df))
    _generate_plot_for(df, 3)
    # df_slow = df[(df['switch'] > 60)]
    # df_slow = df_slow[(df_slow["no_switch"] > 60)]
    # print(len(df_slow))
    # _generate_plot_for(df_slow, 0)
    # df_fast = df[(df['switch'] <= 60)]
    # df_fast = df_fast[(df_fast['no_switch'] <= 60)]
    # print(len(df_fast))
    # _generate_plot_for(df_fast, 1)
    # df_remaining1 = df[(df['switch'] < 60)]
    # df_remaining1 = df_remaining1[(df_remaining1['no_switch'] >= 60)]
    # df_remaining2 = df[(df['switch'] >= 60)]
    # df_remaining2 = df_remaining2[(df_remaining2['no_switch'] < 60)]
    # df_remaining = pd.concat([df_remaining1, df_remaining2])
    # print(len(df_remaining))
    # _generate_plot_for(df_remaining, 2)


def _generate_plot_for(df, i):
    df["switch_log"] = log10(df["switch"])
    df["no_switch_log"] = log10(df["no_switch"])
    color_list = ["#66C4A0", "#EB9DA5"]
    # fig = px.violin(df, x=df["time"], box=True, width=600, height=200, color=df["branch"], color_discrete_sequence=color_list)
    # fig.update_layout(
    #     legend_title="", xaxis_title="Time (seconds)", plot_bgcolor="rgb(0.95,0.95,0.95)", margin = dict(b=5, t=5, r=5, l=5), violinmode="group", violingap=0
    # )
    fig = go.Figure()
    fig.add_trace(go.Violin(x=df["switch_log"], name=" ", box_visible=True, line_color=color_list[0], showlegend=False, opacity=1,
                            meanline_visible=True))
    fig.add_trace(go.Violin(x=df["no_switch_log"], name="", box_visible=True, line_color=color_list[1], showlegend=False, opacity=1,
                            meanline_visible=True))

    # Generate labels for x-axis (logarithmic scale)
    tickvals = [-0.5, 0, 0.5, 1, 1.5, 2, 2.5]
    ticktext = [r"$10^{" + str(val) + r"}s$" for val in tickvals]

    fig.update_layout(
        xaxis=dict(
            tickvals=tickvals,
            ticktext=ticktext,
        ),
        plot_bgcolor="rgb(0.965,0.965,0.965)",
        margin=dict(b=5, t=5, r=5, l=5),
        violingap=0,
        violingroupgap=0.25,
        font=dict(family="Serif",color='black',size=12),
        violinmode="overlay",
        width=400,
        height=120,
    )

    fig.write_image(f"{FIGNAME[i]}.svg")
    fig.write_image(f"{FIGNAME[i]}.pdf", format="pdf")
    # fig.show()

if __name__ == "__main__":
    data_processor = DataProcessor()
    data_processor.process()
    data_processor.render_results()
    generate_plot()
