#!/bin/bash
python3 /root/scanner/scanner_code/scanner_wrapper/scan.py /root/scanner/vulpy /root/scanner/scanner_code/scanner_rules
python3 /root/scanner/scanner_code/scanner_wrapper/json_to_html.py /root/scanner/scanner_code/scanner_wrapper/output.json  /var/www/html/

