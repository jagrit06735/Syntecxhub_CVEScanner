# Syntecxhub CVE Scanner

A lightweight Python-based Vulnerability / CVE Scanner developed as part of the Syntecxhub Cybersecurity Internship.

## Features

- Detects open network services and ports
- Performs banner grabbing
- Extracts service and version information
- Queries the NVD CVE database
- Identifies potential CVE matches
- Displays CVE severity and CVSS scores
- Generates a detailed text report
- Generates a JSON report
- Provides a severity summary

## Technologies Used

- Python
- Requests
- Socket Programming
- NVD CVE API
- JSON

## Project Structure

```text
Syntecxhub_CVEScanner/
│
├── cve_scanner.py
├── requirements.txt
├── scan_report.txt
├── cve_report.json
└── README.md
