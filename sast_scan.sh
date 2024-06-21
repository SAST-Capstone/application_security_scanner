#!/bin/bash

SCANNER_PATH=$(pwd)
echo "Scanner Path: $SCANNER_PATH"
RULES="scanner_code/scanner_rules"
WRAPPER="scanner_code/scanner_wrapper"

REPO_NAME=$(basename $GITHUB_REPOSITORY)
CODE_TO_SCAN="/home/runner/work/$REPO_NAME/$REPO_NAME"

# Run the scan
python3 $SCANNER_PATH/$WRAPPER/sast_scan.py $CODE_TO_SCAN $SCANNER_PATH/$RULES/custom_rules

# Ensure scan results exist before sending
RESULTS_FILE="$SCANNER_PATH/$WRAPPER/scan_results.json"
if [ -f "$RESULTS_FILE" ]; then
    # Send the results to the database
    python3 $SCANNER_PATH/$WRAPPER/send_results.py $RESULTS_FILE
else
    echo "Scan results file not found!"
    exit 1
fi
