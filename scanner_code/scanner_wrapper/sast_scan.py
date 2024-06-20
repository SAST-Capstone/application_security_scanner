import logging
import sys
import os
import json
import subprocess
import zipfile
from io import BytesIO
from openai import OpenAI

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize OpenAI client
openai_api_key = os.getenv('OPENAI_API_KEY')
client = OpenAI(api_key=openai_api_key)

def get_gpt_suggestion(code_snippet):
    messages = [
        {"role": "system", "content": "You are a specialized AI system expert in analyzing vulnerable Python code for the specific vulnerabilities "
                                      "which are ONLY SQL injection, command injection, code injection, SSTI, and SSRF. Review the Python code provided and identify any potential vulnerabilities and give suggestions to fix them. "},
        {"role": "user", "content": f"Provide a suggestion to fix the following code vulnerability:\n\n{code_snippet}"}
    ]
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        max_tokens=150
    )
    suggestion = response.choices[0].message.content.strip()
    return suggestion

def scan_code(file_path: str, rules_path: str) -> str:
    try:
        semgrep_command = [
            "semgrep", "--config", rules_path, "--json", file_path
        ]
        logger.info(f"Running command: {' '.join(semgrep_command)}")
        semgrep_output = subprocess.check_output(semgrep_command, cwd=os.path.dirname(file_path), stderr=subprocess.STDOUT)
        semgrep_output_str = semgrep_output.decode("utf-8")
        logger.info(f"Semgrep output:\n{semgrep_output_str}")

        json_start_idx = semgrep_output_str.index('{')
        json_output = semgrep_output_str[json_start_idx:].strip()
        return json_output
    except subprocess.CalledProcessError as e:
        logger.error(f"Semgrep failed: {e.output.decode('utf-8')}")
        raise
    except ValueError:
        raise ValueError("No JSON output found in Semgrep output")

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
                "Provide the output in JSON format with the following keys: Vulnerability Name, File Path, Suspected Code, and Suggestion (give suggestion fo
