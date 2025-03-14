# Switch Recovery Evaluation Scripts

This repository contains the evaluation scripts for our paper on switch recovery "A Jump-Table-Agnostic Switch Recovery on ASTs".

## Setup

1. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

2. Ensure that the following decompilers are installed and set up:
    - IDA/Hex-Rays
    - Ghidra (requires Java Runtime)
    - dewolf (requires Binary Ninja)

3. Clone the dewolf repository inside this directory and set up the correct version including the switch recovery as mentioned in the paper.
4. Copy Ghidra into this folder (into a folder named `ghidra`) or adjust the path in `decompilers/decompile_ghidra.py`

## Evaluation Steps

### 1. Create the Data Set

As mentioned in the paper, we used coreutils-9.3.
Follow the directions below to download and compile it with GCC:

```sh
wget http://ftp.gnu.org/gnu/coreutils/coreutils-9.3.tar.xz
tar -xf coreutils-9.3.tar.xz
cd coreutils-9.3
./configure
make
```

**Note: Make sure to move the coreutils binaries into a dataset directory for the following scripts to work.**

### 2. Decompile Coreutils Samples
Decompile all coreutils samples and all functions of these samples with every decompiler using the scripts in the decompilers directory:

```
python decompilers/decompile_ida.py
python decompilers/decompile_ghidra.py
python decompilers/decompile_dewolf.py
```

**

### 3. Count Switches in Decompiler Outputs
Use the `count_switches_in_decompiler_outputs.py` script to parse all outputs and count the emitted switch constructs:
```
python count_switches_in_decompiler_outputs.py
```

### 4. Compare and Evaluate Switches
Finally, compare and evaluate the emitted switches using the `generate_evaluation_results.py` script:
```
python generate_evaluation_results.py
```

**Note: Make sure to adjust the paths in the script files depending on your output paths.**

## Runtime Evaluation

For the runtime evaluation, consider the scripts in `runtime` that can be used to generate the plots from the paper, based on previously generated decompiler outputs from dewolf with and without enabled switch recovery.
See the respective dewolf documentation for how to disable switch recovery.