#!/bin/bash

SCANNER_PATH=$(pwd)
echo "Scanner Path: $SCANNER_PATH"
RULES="scanner_code/scanner_rules"
WRAPPER="scanner_code/scanner_wrapper"

# Extract the repository name from the GITHUB_REPOSITORY environment variable
REPO_NAME=$(basename $GITHUB_REPOSITORY)
echo "Repository Name: $REPO_NAME"

# Set the CODE_TO_SCAN path dynamically
CODE_TO_SCAN="/home/runner/work/$REPO_NAME/$REPO_NAME"
echo "Code to Scan: $CODE_TO_SCAN"

# Run the scan
python3 $SCANNER_PATH/$WRAPPER/sast_scan.py $CODE_TO_SCAN $SCANNER_PATH/$RULES/custom_rules

# Send the results to the database
if [ -f "$SCANNER_PATH/$WRAPPER/scan_results.json" ]; then
    python3 $SCANNER_PATH/$WRAPPER/send_results.py $SCANNER_PATH/$WRAPPER/scan_results.json
else
    echo "Scan results file not found!"
    exit 1
fi
