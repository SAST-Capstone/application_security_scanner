import json
import requests
import sys
import os
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def load_scan_results(file_path):
    try:
        with open(file_path, 'r') as file:
            scan_results = json.load(file)
        return scan_results
    except FileNotFoundError:
        logger.error(f"Scan results file {file_path} not found!")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing scan results file {file_path}: {e}")
        sys.exit(1)

def send_results_to_database(scan_results, api_key):
    url = 'http://127.0.0.1:8000/save_scan_results/'  # Replace with your server's URL
    headers = {
        'Authorization': f'Token {api_key}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(url, headers=headers, json=scan_results)
        response.raise_for_status()
        logger.info(f"Scan results sent successfully. Server response: {response.json()}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send scan results: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python send_results.py <path_to_scan_results>")
        sys.exit(1)

    scan_results_file = sys.argv[1]
    api_key = os.getenv('MODULE_API_KEY')

    scan_results = load_scan_results(scan_results_file)
    send_results_to_database(scan_results, api_key)
