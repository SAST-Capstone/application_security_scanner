import sys
import os
import json 


def get_inputs() -> str:
    # replace sys.argv with  parser = argparse.ArgumentParser()
    code_to_scan_path = sys.argv[1]
    rules_path = sys.argv[2]
    return code_to_scan_path, rules_path


def build_semgrep_command(code: str, rules_path: str) -> str:
    semgrep_command = "semgrep " + code + " --config=" + rules_path + " --json"
    return semgrep_command


def run_semgrep_command(semgrep_command) -> str:
    semgrep_output = os.popen(semgrep_command).read()
    return semgrep_output


def write_output_to_file(file_name: str,scanner_output: str):
    output_file = open(file_name, "w")
    output_file.write(scanner_output)


def main():
    output_file_name = "output.json"
    code,rules = get_inputs()
    command = build_semgrep_command(code,rules)
    scanner_output = run_semgrep_command(command)
    write_output_to_file(output_file_name, scanner_output)


if __name__ == "__main__":
    main()