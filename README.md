# Finding TTPs with symbolic execution

# Debugging detection
There is an example with instructions in `mini_debug_detection.c`

In `liblzma.so.5.6.1.s` there is the objdump of the XZ version with the backdoor.
Look for the word "HERE" to find there the debug detection is made.

# JASM
You can find everything you need in the `JASM` repo:
https://github.com/JukMR/JASM

```bash
git clone git@github.com:JukMR/JASM.git
cd JASM
poetry shell
poetry install

python3 main.py -p <pattern.yaml> -b <binary_file.bin>
```
There's a JASM rule example in `sw_breakpoint_jasm_rule.yaml`

# Dangr

How to run Dangr examples?

```bash
$ poetry shell
$ poetry install
$ python examples/<n_example>.py
```
