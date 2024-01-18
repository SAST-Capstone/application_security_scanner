import sys
import os
import json

def get_inputs() -> tuple:
    if len(sys.argv) < 4:
        raise ValueError("Not enough arguments. Usage: scan.py <code_path> <rules_path> <output_file>")
    code_to_scan_path = sys.argv[1]
    rules_path = sys.argv[2]
    output_file_path = sys.argv[3]
    return code_to_scan_path, rules_path, output_file_path

def build_semgrep_command(code: str, rules_path: str) -> str:
    semgrep_command = "semgrep " + code + " --config=" + rules_path + " --json"
    return semgrep_command

def run_semgrep_command(semgrep_command) -> str:
    semgrep_output = os.popen(semgrep_command).read()
    return semgrep_output

def write_output_to_file(file_path: str, scanner_output: str):
    with open(file_path, "w") as output_file:
        output_file.write(scanner_output)

def main():
    try:
        code, rules, output_file = get_inputs()
        command = build_semgrep_command(code, rules)
        scanner_output = run_semgrep_command(command)
        write_output_to_file(output_file, scanner_output)
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
