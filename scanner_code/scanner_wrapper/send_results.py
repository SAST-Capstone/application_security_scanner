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
    url = 'https://1e5c-2001-8f8-1539-2251-789d-8474-a3d8-d6cc.ngrok-free.app/save_scan_results/'  # Replace with your server's URL
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

    logger.info(f"Looking for scan results at {scan_results_file}")
    if not os.path.isfile(scan_results_file):
        logger.error(f"Scan results file {scan_results_file} does not exist.")
        sys.exit(1)

    scan_results = load_scan_results(scan_results_file)
    send_results_to_database(scan_results, api_key)
