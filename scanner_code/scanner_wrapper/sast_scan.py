import logging
import sys
import os
import json
import subprocess
import zipfile
from io import BytesIO
import openai
import requests
from time import sleep

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize OpenAI API client
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
openai.api_key = OPENAI_API_KEY

def get_gpt_suggestion(code_snippet):
    messages = [
        {"role": "system", "content": "You are a specialized AI system expert in analyzing vulnerable Python code for the specific vulnerabilities "
                                      "which are ONLY SQL injection, command injection, code injection, SSTI, and SSRF. Review the Python code provided and identify any potential vulnerabilities and give suggestions to fix them."},
        {"role": "user", "content": f"Provide a suggestion to fix the following code vulnerability:\n\n{code_snippet}"}
    ]
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=messages,
        max_tokens=150
    )
    suggestion = response.choices[0].message.content.strip()
    return suggestion

def scan_code(file_paths: list, rules_path: str) -> list:
    all_results = []
    try:
        for file_path in file_paths:
            logger.debug(f"Checking existence of file: {file_path}")
            if not os.path.isfile(file_path):
                logger.error(f"File {file_path} is not a valid file.")
                raise FileNotFoundError(f"File {file_path} not found or is not a file.")

        logger.debug(f"Checking existence of rules path: {rules_path}")
        if not os.path.isdir(rules_path):
            logger.error(f"Rules path {rules_path} is not a valid directory.")
            raise FileNotFoundError(f"Rules path {rules_path} not found or is not a directory.")

        logger.debug(f"Listing rules files in {rules_path}")
        for root, dirs, files in os.walk(rules_path):
            for file in files:
                logger.debug(f"Found rule file: {file}")

        for file_path in file_paths:
            semgrep_command = [
                "semgrep", "--config", rules_path, "--json", file_path
            ]
            logger.info(f"Running command: {' '.join(semgrep_command)}")
            try:
                semgrep_output = subprocess.check_output(semgrep_command, cwd=os.path.dirname(file_path), stderr=subprocess.STDOUT)
                semgrep_output_str = semgrep_output.decode("utf-8")
                logger.info(f"Semgrep output:\n{semgrep_output_str}")

                json_start_idx = semgrep_output_str.index('{')
                json_output = semgrep_output_str[json_start_idx:].strip()
                semgrep_results = json.loads(json_output)
                
                for result in semgrep_results.get('results', []):
                    code_snippet = result["extra"]["lines"]
                    suggestion = get_gpt_suggestion(code_snippet)
                    result["suggestion"] = suggestion

                all_results.extend(semgrep_results.get('results', []))
            except subprocess.CalledProcessError as e:
                logger.error(f"Semgrep failed: {e.output.decode('utf-8')}")
                raise

    except Exception as e:
        logger.error(f"Error during scanning: {e}")
        raise
    return all_results

def parse_semgrep_output(semgrep_output: str):
    try:
        return json.loads(semgrep_output)
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing Semgrep output: {e}")
        raise

def analyze_python_code(code, filename):
    messages = [
        {
            "role": "system",
            "content": (
                "You are a specialized AI system expert in Static Application Security Testing to analyze Python code for the specific vulnerabilities "
                "which are ONLY SQL-injection, command-injection, code-injection, SSTI, and SSRF. Review the Python code provided and identify any potential vulnerabilities. "
                "Provide the output in JSON format with the following keys: Vulnerability Name, File Path, Suspected Code, and Suggestion (give suggestion for fixing)."
                "Vulnerability Name should be as follows: SQL-injection, Command-Injection, Code-Injection, SSTI, or SSRF"
            )
        },
        {
            "role": "user",
            "content": f"Filename: {filename}\n\nPlease analyze the code below for potential security vulnerabilities:\n\n{code}\n\nPlease provide the output in JSON format."
        }
    ]
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=messages,
        max_tokens=1024
    )
    output_text = response.choices[0].message.content.strip()
    try:
        if output_text.startswith("```json"):
            output_text = output_text[7:-3].strip()
        result_list = json.loads(output_text)
        logger.debug(f"Parsed GPT Result: {result_list}")
        return result_list
    except json.JSONDecodeError as e:
        logger.error(f"JSONDecodeError: {e}")
        return [{
            "Vulnerability Name": "Error",
            "File Path": filename,
            "Suspected Code": "",
            "Suggestion": "Check the API response and ensure it is in the correct format."
        }]
    except Exception as e:
        logger.error(f"Error: {e}")
        return [{
            "Vulnerability Name": "Error",
            "File Path": filename,
            "Suspected Code": "",
            "Suggestion": "Check the API response and ensure it is in the correct format."
        }]

def analyze_files_or_zip(uploaded_file):
    uploaded_file.seek(0)
    file_content = uploaded_file.read()
    results = []
    if zipfile.is_zipfile(BytesIO(file_content)):
        with zipfile.ZipFile(BytesIO(file_content), 'r') as zip_file:
            for name in zip_file.namelist():
                if name.endswith('.py'):
                    with zip_file.open(name) as file_in_zip:
                        code = file_in_zip.read().decode('utf-8')
                        result = analyze_python_code(code, name)
                        results.extend(result)
    else:
        code = file_content.decode('utf-8')
        result = analyze_python_code(code, uploaded_file.name)
        results.extend(result)
    return results

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sast_scan.py <path_to_code> <path_to_rules>")
        sys.exit(1)
    code_path = sys.argv[1]
    rules_path = sys.argv[2]

    try:
        # Collect all Python files in the user repository directory
        files_to_scan = []
        if os.path.isdir(code_path):
            for root, _, files in os.walk(code_path):
                # Exclude the application_security_scanner directory
                if 'application_security_scanner' in root:
                    continue
                for file in files:
                    if file.endswith('.py'):
                        files_to_scan.append(os.path.join(root, file))
        else:
            files_to_scan.append(code_path)

        scan_results = scan_code(files_to_scan, rules_path)

        # Save the results to a file
        results_file = os.path.join(os.path.dirname(__file__), 'scan_results.json')
        with open(results_file, "w") as f:
            json.dump({"results": scan_results}, f, indent=4)
        print(f"Scan results saved to {results_file}")

        # # Attempt to send the scan results
        # if not send_scan_results(results_file):
        #     print("Failed to send scan results to server. Results are saved locally.")

    except Exception as e:
        logger.error(f"Error: {e}")
        print("Scan results file not found!")
        sys.exit(1)
