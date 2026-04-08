# 🔍 SQL Injection Detector

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3-green)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Web%20%7C%20API-lightgrey)]()

A comprehensive security testing tool designed to identify SQL injection vulnerabilities in web applications through automated payload testing and intelligent detection algorithms.

## 🚀 Features

- **Multiple Detection Methods**
  - Error-based SQL injection detection
  - Time-based blind SQL injection testing
  - UNION-based query detection
  - Boolean-based blind detection

- **Attack Vectors**
  - GET parameter testing
  - POST data testing
  - Header injection testing
  - Cookie-based injection

- **Reporting & Output**
  - Real-time web dashboard
  - JSON API responses
  - Detailed vulnerability reports
  - Risk severity classification

- **Payload Database**
  - 50+ tested SQL injection payloads
  - MySQL, PostgreSQL, MSSQL, Oracle specific
  - Custom payload support

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.8+, Flask |
| Frontend | HTML5, CSS3, JavaScript |
| Testing | Requests, BeautifulSoup |
| Security | urllib.parse, SQLMap inspired |

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/olanitedaniel/sql-injection-detector.git
cd sql-injection-detector

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run application
python app.py
