#!/bin/bash

# this is a shell script

# did I mention that shell scripts are kinda ugly?

# the weird "$@" syntax below means that whatever command-line
# arguments are passed to run-me.sh will be passed again to the Python
# program called hw1.py.

python -u EncryptedIM.py $@

# but that's for python.  If you did it in C and you produced a program
# called hw1, then it'd be more like:
#   ./hw1 $@

# but that's for C.  If you did it in Java and you produced a program
# called Hw1.class, then it'd be more like:
#   java Hw1 $@
