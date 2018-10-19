#!/bin/bash

# this is a shell script

# did I mention that shell scripts are kinda ugly?

# the weird "$@" syntax below means that whatever command-line
# arguments are passed to run-me.sh will be passed again to the Python
# program called EncryptedIM.py.

python -u EncryptedIM.py $@
