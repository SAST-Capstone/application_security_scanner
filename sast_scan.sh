#!/bin/bash

SCANNER_PATH=$(pwd)
echo "Scanner Path: $SCANNER_PATH"
RULES="$SCANNER_PATH/scanner_code/scanner_rules/python-sql-injection.yaml"
WRAPPER="$SCANNER_PATH/scanner_code/scanner_wrapper"

# Extract the repository name from the GITHUB_REPOSITORY environment variable
REPO_NAME=$(basename $GITHUB_REPOSITORY)
echo "Repository Name: $REPO_NAME"

# Set the CODE_TO_SCAN path dynamically
CODE_TO_SCAN="/home/runner/work/$REPO_NAME/$REPO_NAME"
echo "Code to Scan: $CODE_TO_SCAN"

MY_RULES="custom_rules"

# Run the scan
python3 "$WRAPPER/sast_scan.py" "$CODE_TO_SCAN" "$RULES/$MY_RULES"

# Check if scan results exist
if [ -f "$WRAPPER/scan_results.json" ]; then
  # Send the results to the database
  python3 "$WRAPPER/send_results.py" "$WRAPPER/scan_results.json"
else
  echo "Scan results file not found!"
  exit 1
fi
