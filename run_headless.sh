#!/bin/bash
# Run a Ghidra script in headless mode

if [ $# -ne 3 ]; then
    echo "Usage: $(basename $0) <ghidra_path> <script_path> <file_path>"
    echo "Options:"
    echo "     ghidra_path  Path to local Ghidra installation"
    echo "     script_path  Path to Ghidra script"
    echo "     file_path    Path to file to analyze"
    exit 1
fi

GHIDRA_PATH=$1
SCRIPT_PATH=$2
FILE_PATH=$3

# If you need to pass arguments to a script, you can't pass through STDIN but we can use environment variables :P
$GHIDRA_PATH/support/analyzeHeadless . tmproject \
    -import $FILE_PATH \
    -postScript $SCRIPT_PATH \
    -deleteProject \
    -noanalysis \
    -processor "86:LE:32:default" \
    -cspec gcc
