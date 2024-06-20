#!/bin/bash

SCANNER_PATH=$(pwd)
echo $SCANNER_PATH
RULES="scanner_code/scanner_rules"
WRAPPER="scanner_code/scanner_wrapper"

# Extract the repository name from the GITHUB_REPOSITORY environment variable
REPO_NAME=$(basename $GITHUB_REPOSITORY)

# Set the CODE_TO_SCAN path dynamically
CODE_TO_SCAN="/home/runner/work/$REPO_NAME/$REPO_NAME"

MY_RULES="custom_rules"

# Run the scan
python3 $SCANNER_PATH/$WRAPPER/sast_scan.py $CODE_TO_SCAN $SCANNER_PATH/$RULES/$MY_RULES

# Send the results to the database
python3 $SCANNER_PATH/$WRAPPER/send_results.py $SCANNER_PATH/$WRAPPER/scan_results.json



