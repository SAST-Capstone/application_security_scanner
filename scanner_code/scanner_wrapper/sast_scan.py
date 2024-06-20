import os
import sys
import subprocess
import requests
import json
import logging
from zipfile import ZipFile
from io import BytesIO
from openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# GPT API client
client = OpenAI(api_key='sk-proj-cl6UF6XJCRlN1dCBHl05T3BlbkFJHQoUUmYusKgpZ44qMLhI')


def get_gpt_suggestion(code_snippet):
    messages = [
        {"role": "system", "content": "You are a specialized AI system expert in analyzing vulnerable Python code for the specific vulnerabilities "
                "which are ONLY SQL injection, command injection, code injection, SSTI, and SSRF. Review the Python code provided and identify any potential vulnerabilities and give suggestions to fix them. "},
        {"role": "user", "content": f"Provide a suggestion to fix the following code vulnerability:\n\n{code_snippet}"}
    ]
    
    response = client.chat.completions.create(model="gpt-4o",  # Use the appropriate engine
    messages=messages,
    max_tokens=150
    )
    suggestion = response.choices[0].message.content.strip()
    return suggestion


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

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        max_tokens=1024
    )

    output_text = response.choices[0].message.content.strip()

    try:
        # Clean the response to ensure it's valid JSON
        if output_text.startswith("```json"):
            output_text = output_text[7:-3].strip()

        # Parse the JSON response to extract the required fields
        result_list = json.loads(output_text)

        # Debug log the result
        logger.debug(f"Parsed GPT Result: {result_list}")

        return result_list  # Return the list of results
    except json.JSONDecodeError as e:
        logger.error(f"JSONDecodeError: {e}")
        logger.error(f"Response text: {output_text}")
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


def scan_code(file_path: str, rules_path: str) -> str:
    try:
        # Ensure the virtual environment's bin directory is in the PATH
        env_path = os.environ.get("PATH", "")
        venv_bin_path = "/home/kali/Desktop/PyCatenaccio/env/bin"
        os.environ["PATH"] = f"{venv_bin_path}:{env_path}"

        # Check if the file is accessible before running Semgrep
        if not os.path.isfile(file_path):
            logger.error(f"File {file_path} is not a valid file.")
            raise FileNotFoundError(f"File {file_path} not found or is not a file.")

        # Run Semgrep with the provided rules path
        semgrep_command = [
            "semgrep", "--config", rules_path, "--json", file_path
        ]
        logger.info(f"Running command: {' '.join(semgrep_command)}")
        logger.debug(f"File to scan: {file_path}")

        # Set working directory to where the file is located
        semgrep_output = subprocess.check_output(semgrep_command, cwd=os.path.dirname(file_path), stderr=subprocess.STDOUT)
        semgrep_output_str = semgrep_output.decode("utf-8")
        logger.info(f"Semgrep output:\n{semgrep_output_str}")

        # Extract JSON part from the output
        try:
            json_start_idx = semgrep_output_str.index('{')
            json_output = semgrep_output_str[json_start_idx:].strip()
            return json_output
        except ValueError:
            raise ValueError("No JSON output found in Semgrep output")
    except subprocess.CalledProcessError as e:
        logger.error(f"Semgrep failed: {e.output.decode('utf-8')}")
        raise


def parse_semgrep_output(semgrep_output: str):
    try:
        return json.loads(semgrep_output)
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing Semgrep output: {e}")
        raise


def main():
    # Retrieve paths from command-line arguments
    if len(sys.argv) != 3:
        logger.error("Usage: scan.py <code_to_scan_path> <rules_path>")
        sys.exit(1)

    code_to_scan = sys.argv[1]
    rules_path = sys.argv[2]
    api_key = os.getenv('API_KEY')

    # Scan files in the user repository using Semgrep
    results = []
    for root, _, files in os.walk(code_to_scan):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                semgrep_output = scan_code(file_path, rules_path)
                semgrep_results = parse_semgrep_output(semgrep_output)
                for result in semgrep_results.get('results', []):
                    rule_name = result['check_id'].split('.')[-1]
                    results.append({
                        "vulnerability_name": rule_name,
                        "file_path": file_path,
                        "suspected_code": result['extra']['lines'],
                        "suggestion": get_gpt_suggestion(result['extra']['lines'])
                    })

    # Scan files in the user repository using GPT
    for root, _, files in os.walk(code_to_scan):
        for file in files:
            if file.endswith('.py'):
                with open(os.path.join(root, file), 'r') as f:
                    code = f.read()
                    gpt_results = analyze_python_code(code, file)
                    results.extend(gpt_results)

    # Send results to the server
    response = requests.post(
        'https://your-web-app.com/api/save_scan_results',
        headers={'Authorization': f'Bearer {api_key}'},
        json=results
    )

    if response.status_code == 200:
        logger.info("Scan results sent successfully.")
    else:
        logger.error(f"Failed to send scan results. Status code: {response.status_code}")

if __name__ == '__main__':
    main()
