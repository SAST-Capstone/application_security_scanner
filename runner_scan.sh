#!/bin/bash

SCANNER_PATH=`pwd`
echo $SCANNER_PATH
RULES="scanner_code/scanner_rules"
WRAPPER="scanner_code/scanner_wrapper"

# Extract the repository name from the GITHUB_REPOSITORY environment variable
REPO_NAME=$(basename $GITHUB_REPOSITORY)

# Set the CODE_TO_SCAN path dynamically
CODE_TO_SCAN="/home/runner/work/$REPO_NAME/$REPO_NAME"

MY_RULES="custom_rules"
python3 $SCANNER_PATH/$WRAPPER/scan.py $CODE_TO_SCAN $SCANNER_PATH/$RULES/$MY_RULES
python3 $SCANNER_PATH/$WRAPPER/json_to_html.py $SCANNER_PATH/output.json /var/www/html/
