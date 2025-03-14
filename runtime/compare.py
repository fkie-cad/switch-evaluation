from __future__ import annotations

import base64
import json
from dataclasses import dataclass, is_dataclass, asdict, field
from datetime import timedelta, datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Literal, Union
from numpy import quantile, average

DEWOLF_SWITCH =    Path("202X-XX-XX-dewolf_main_coreutils_switch.json")
DEWOLF_NO_SWITCH = Path("202X-XX-XX-dewolf_main_coreutils_without_switch.json")
OUTPUT_PATH =      Path("202X-XX-XX-output_coreutils.json")

TOLERANCE_ABSOLUTE = 5  # in seconds
TOLERANCE_RELATIVE = 1.1  # percentage --> 1.1 is 10% tolerance is allowed

# BOXPLOT Ranges in seconds:
LB = 0 * 60
UB = 5 * 60


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


@dataclass
class BoxPlotData:
    min_value: float
    max_value: float
    median: float
    mean: float
    first_quantil: float
    third_quantil: float
    wiskers: Tuple[float, float]
    outliers: List[float]

    @classmethod
    def generate_from(cls, data: List[float]) -> BoxPlotData:
        min_value = min(data)
        max_value = max(data)
        median = quantile(data, 0.5)
        mean = average(data)
        first_quantil = quantile(data, 0.25)
        third_quantil = quantile(data, 0.75)
        offset = 1.5 * (third_quantil - first_quantil)
        wiskers = (max(min_value, first_quantil - offset), min(max_value, third_quantil + offset))
        outliers = [d for d in data if d < wiskers[0] or d > wiskers[1]]
        return cls(min_value, max_value, median, mean, first_quantil, third_quantil, wiskers, outliers)

    def __str__(self) -> str:
        return (
            f"min: {self.min_value}, max: {self.max_value}, median: {self.median}, mean: {self.mean}, "
            f"first-quantil: {self.first_quantil}, third-quantil: {self.third_quantil}, wiskers: ({self.wiskers[0]}, {self.wiskers[1]}), outliers: [{','.join(str(o) for o in self.outliers)}]"
        )


@dataclass
class ResultData:
    timeout_only_with_switch: List[FunctionIdentifier] = field(default_factory=list)
    timeout_only_without_switch: List[FunctionIdentifier] = field(default_factory=list)
    error_only_without_switch: List[FunctionIdentifier] = field(default_factory=list)
    error_only_with_switch: List[FunctionIdentifier] = field(default_factory=list)
    without_switch_faster: List[FunctionIdentifier] = field(default_factory=list)
    with_switch_faster: List[FunctionIdentifier] = field(default_factory=list)
    timeout_switch_error_no_switch: List[FunctionIdentifier] = field(default_factory=list)
    error_switch_timeout_no_switch: List[FunctionIdentifier] = field(default_factory=list)
    no_switch_box_plot: Optional[BoxPlotData] = None
    switch_box_plot: Optional[BoxPlotData] = None


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
                continue

            self._result[function_identifier] = tuple(
                self._decompiler_data_of[branch][function_identifier] for branch in ["switch", "no_switch"]
            )
        # with open(OUTPUT_PATH, "w") as outfile:
        #     json.dump({str(f_id): data for f_id, data in self._result.items()}, outfile, cls=EnhancedJSONEncoder, indent=2)

    def _not_all_decompilers_decompiled(self, function_identifier: FunctionIdentifier) -> bool:
        return function_identifier not in self._decompiler_data_of["no_switch"]

    def render_results(self):
        result = self._compute_data()

        with open(OUTPUT_PATH, "w") as outfile:
            json.dump(
                {
                    "samples where switch reconstruction results in a timeout and no switch produces an output": result.timeout_only_with_switch,
                    "samples where no switch reconstruction results in a timeout and switch produces an output": result.timeout_only_without_switch,
                    "samples where switch reconstruction results in an error and no switch produces an output": result.error_only_with_switch,
                    "samples where no switch reconstruction results in an error and switch produces an output": result.error_only_without_switch,
                    "samples where no switch reconstruction is faster": result.without_switch_faster,
                    "samples where switch reconstruction is faster": result.with_switch_faster,
                    "samples where we have a timeout with switch reconstruction and an error without switch construction" : result.timeout_switch_error_no_switch,
                    "samples where we have an error with switch reconstruction and a timeout without switch construction" : result.error_switch_timeout_no_switch,
                    "box-plot timing without switch": result.no_switch_box_plot,
                    "box-plot timing with switch": result.switch_box_plot,
                },
                outfile,
                cls=EnhancedJSONEncoder,
                indent=2,
                sort_keys=True,
            )
        print(
            json.dumps(
                {
                    "number of samples where switch reconstruction results in a timeout and no switch produces an output": len(result.timeout_only_with_switch),
                    "number of samples where no switch reconstruction results in a timeout and switch produces an output": len(result.timeout_only_without_switch),
                    "number of samples where switch reconstruction results in an error and no switch produces an output": len(result.error_only_with_switch),
                    "number of samples where no switch reconstruction results in an error and switch produces an output": len(result.error_only_without_switch),
                    "number of samples where no switch reconstruction is faster": len(result.without_switch_faster),
                    "number of samples where switch reconstruction is faster": len(result.with_switch_faster),
                    "number of samples where we have a timeout with switch reconstruction and an error without switch construction": len(result.timeout_switch_error_no_switch),
                    "number of samples where we have an error with switch reconstruction and a timeout without switch construction": len(result.error_switch_timeout_no_switch),
                    "box-plot timing without switch": str(result.no_switch_box_plot),
                    "box-plot timing with switch": str(result.switch_box_plot),
                },
                indent=4,
                sort_keys=True,
            )
        )

        # print("Consider samples \n")
        # for func in result.new_timeouts + result.new_errors:
        #     print(func)

    def _compute_data(self):
        switch_times = list()
        no_switch_times = list()
        result_data = ResultData()
        max_switch_time = 0
        max_no_switch_time = 0
        max_time = 0
        for function, (switch_data, no_switch_data) in self._result.items():
            if switch_data.time != "inf":
                max_switch_time = max(max_switch_time, switch_data.time)
            if no_switch_data.time != "inf":
                max_no_switch_time = max(max_no_switch_time, no_switch_data.time)
            if switch_data.time != "inf" and no_switch_data.time != "inf":
                max_time = max(max_time, switch_data.time, no_switch_data.time)
            match (switch_data.code == "TimeOut", switch_data.has_error, no_switch_data.code == "TimeOut", no_switch_data.has_error):
                case(True, _, False, True):
                    result_data.timeout_switch_error_no_switch.append(function)
                case(False, True, True, _):
                    result_data.error_switch_timeout_no_switch.append(function)
                case (True, _, False, False):
                    result_data.timeout_only_with_switch.append(function)
                case (False, False, True, _):
                    result_data.timeout_only_without_switch.append(function)
                case ( _ ,True, False, False):
                    result_data.error_only_with_switch.append(function)
                case (False, False, _, True):
                    result_data.error_only_without_switch.append(function)
                case (False, False, False, False):
                    if TOLERANCE_RELATIVE * switch_data.time < no_switch_data.time and switch_data.time + TOLERANCE_ABSOLUTE < no_switch_data.time:
                        result_data.with_switch_faster.append(function)
                    elif TOLERANCE_RELATIVE * no_switch_data.time < switch_data.time and no_switch_data.time + TOLERANCE_ABSOLUTE < switch_data.time:
                        result_data.without_switch_faster.append(function)
                    if LB <= switch_data.time <= UB and LB <= no_switch_data.time <= UB:
                        switch_times.append(switch_data.time)
                        no_switch_times.append(no_switch_data.time)

        # Box Plot only if both have a result
        print(f"Max runtime with switch {max_switch_time}")
        print(f"Max runtime without switch {max_no_switch_time}")
        print(f"Max runtime bot {max_time}")
        result_data.switch_box_plot = BoxPlotData.generate_from(switch_times)
        result_data.no_switch_box_plot = BoxPlotData.generate_from(no_switch_times)

        return result_data


if __name__ == "__main__":
    data_processor = DataProcessor()
    data_processor.process()
    data_processor.render_results()
