import os
import json
import subprocess
import logging
import sys

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Replace with your OpenAI API key
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

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

def save_scan_results(scan_results, file_path):
    try:
        with open(file_path, 'w') as file:
            json.dump(scan_results, file, indent=4)
        logger.info(f"Scan results saved to {file_path}")
    except IOError as e:
        logger.error(f"Failed to save scan results to {file_path}: {e}")
        raise

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sast_scan.py <path_to_code> <path_to_rules>")
        sys.exit(1)

    code_path = sys.argv[1]
    rules_path = sys.argv[2]

    logger.debug(f"Checking existence of file: {code_path}")
    logger.debug(f"Checking existence of rules path: {rules_path}")

    try:
        semgrep_output = scan_code(code_path, rules_path)
        scan_results = parse_semgrep_output(semgrep_output)

        results_file_path = os.path.join(os.path.dirname(__file__), 'scan_results.json')
        save_scan_results(scan_results, results_file_path)
    except Exception as e:
        logger.error(f"Error during scanning: {e}")
        sys.exit(1)
