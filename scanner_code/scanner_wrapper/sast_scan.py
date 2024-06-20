import logging
import os
import sys
import json
import subprocess
import zipfile
from io import BytesIO
from openai import OpenAI

# Initialize OpenAI client with API key from environment variable
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

logger = logging.getLogger(__name__)

# Function to get GPT suggestion for a code snippet
def get_gpt_suggestion(code_snippet):
    messages = [
        {"role": "system", "content": "You are a specialized AI system expert in analyzing vulnerable Python code for the specific vulnerabilities "
                "which are ONLY SQL injection, command injection, code injection, SSTI, and SSRF. Review the Python code provided and identify any potential vulnerabilities and give suggestions to fix them. "},
        {"role": "user", "content": f"Provide a suggestion to fix the following code vulnerability:\n\n{code_snippet}"}
    ]
    
    response = client.chat.completions.create(model="gpt-4o", messages=messages, max_tokens=150)
    suggestion = response.choices[0].message.content.strip()
    return suggestion

# Function to perform rule-based scan using Semgrep
def scan_code(file_path: str, rules_path: str) -> str:
    try:
        if not os.path.isfile(file_path):
            logger.error(f"File {file_path} is not a valid file.")
            raise FileNotFoundError(f"File {file_path} not found or is not a file.")

        semgrep_command = ["semgrep", "--config", rules_path, "--json", file_path]
        logger.info(f"Running command: {' '.join(semgrep_command)}")
        logger.debug(f"File to scan: {file_path}")

        semgrep_output = subprocess.check_output(semgrep_command, cwd=os.path.dirname(file_path), stderr=subprocess.STDOUT)
        semgrep_output_str = semgrep_output.decode("utf-8")
        logger.info(f"Semgrep output:\n{semgrep_output_str}")

        json_start_idx = semgrep_output_str.index('{')
        json_output = semgrep_output_str[json_start_idx:].strip()
        return json_output

    except subprocess.CalledProcessError as e:
        logger.error(f"Semgrep failed: {e.output.decode('utf-8')}")
        raise

def parse_semgrep_output(semgrep_output: str):
    try:
        return json.loads(semgrep_output)
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing Semgrep output: {e}")
        raise

# Function to analyze Python code using GPT
def analyze_python_code(code, filename):
    messages = [
        {
            "role": "system",
            "content": (
                "You are a specialized AI system expert in Static Application Security Testing to analyze Python code for the specific vulnerabilities "
                "which are ONLY SQL-injection, command-injection, code-injection, SSTI, and SSRF. Review the Python code provided and identify any potential vulnerabilities. "
                "Provide the output in JSON format with the following keys: Vulnerability Name, File Path, Suspected Code, and Suggestion (give suggestion for fixing)."
                "Vulnerability Name should be one of: SQL-injection, Command-Injection, Code-Injection, SSTI, or SSRF"
            )
        },
        {
            "role": "user",
            "content": f"Filename: {filename}\n\nPlease analyze the code below for potential security vulnerabilities:\n\n{code}\n\nPlease provide the output in JSON format."
        }
    ]

    response = client.chat.completions.create(model="gpt-4o", messages=messages, max_tokens=1024)
    output_text = response.choices[0].message.content.strip()

    try:
        if output_text.startswith("```json"):
            output_text = output_text[7:-3].strip()
        result_list = json.loads(output_text)
        print(f"Parsed GPT Result: {result_list}")
        return result_list

    except json.JSONDecodeError as e:
        print(f"JSONDecodeError: {e}")
        print(f"Response text: {output_text}")
        return [{
            "Vulnerability Name": "Error",
            "File Path": filename,
            "Suspected Code": "",
            "Suggestion": "Check the API response and ensure it is in the correct format."
        }]

    except Exception as e:
        print(f"Error: {e}")
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

    code_to_scan = sys.argv[1]
    rules_path = sys.argv[2]

    if os.path.isfile(code_to_scan):
        # Process a single file
        semgrep_output = scan_code(code_to_scan, rules_path)
        scan_results = parse_semgrep_output(semgrep_output)

        # Add GPT suggestions
        for result in scan_results['results']:
            code_snippet = result['extra']['lines']
            suggestion = get_gpt_suggestion(code_snippet)
            result['suggestion'] = suggestion

    elif os.path.isdir(code_to_scan):
        # Process all Python files in the directory
        for root, _, files in os.walk(code_to_scan):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    semgrep_output = scan_code(file_path, rules_path)
                    scan_results = parse_semgrep_output(semgrep_output)

                    # Add GPT suggestions
                    for result in scan_results['results']:
                        code_snippet = result['extra']['lines']
                        suggestion = get_gpt_suggestion(code_snippet)
                        result['suggestion'] = suggestion

    # Save results to a JSON file
    with open("scan_results.json", "w") as f:
        json.dump(scan_results, f, indent=4)
