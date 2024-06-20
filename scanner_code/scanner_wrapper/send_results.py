import requests
import json
import os
import sys

def send_results_to_database(results_file, api_key):
    with open(results_file, 'r') as f:
        scan_results = json.load(f)
    
    url = "http://127.0.0.1:8000/api/save_scan_results/"
    headers = {
        "Authorization": f"Token {api_key}",
        "Content-Type": "application/json"
    }
    
    response = requests.post(url, headers=headers, json=scan_results)
    
    if response.status_code == 201:
        print("Scan results sent successfully!")
    else:
        print(f"Failed to send scan results: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python send_results.py <path_to_results_json>")
        sys.exit(1)
    
    results_file = sys.argv[1]
    api_key = os.getenv('MODULE_API_KEY')
    
    if not api_key:
        print("MODULE_API_KEY environment variable not set.")
        sys.exit(1)
    
    send_results_to_database(results_file, api_key)
