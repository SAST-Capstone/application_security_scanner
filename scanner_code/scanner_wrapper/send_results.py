import requests
import sys
import json
import os

# Load the scan results from the specified JSON file
def load_scan_results(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Send the scan results to the database
def send_scan_results(api_key, scan_results):
    url = 'http://127.0.0.1:8000/save_scan_results/'  # Replace with your actual server URL
    headers = {
        'Authorization': f'Token {api_key}',
        'Content-Type': 'application/json'
    }
    response = requests.post(url, headers=headers, json=scan_results)
    if response.status_code == 201:
        print("Scan results saved successfully!")
    else:
        print(f"Failed to save scan results: {response.status_code} - {response.text}")

if __name__ == '__main__':
    scan_results_file = sys.argv[1]
    api_key = os.getenv('MODULE_API_KEY')

    if not api_key:
        print("API key not found in environment variables")
        sys.exit(1)

    scan_results = load_scan_results(scan_results_file)
    send_scan_results(api_key, scan_results)
