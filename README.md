# Security Log Analyzer

A Python-based security log analysis tool that detects suspicious authentication activity.

## Overview

This project analyzes authentication logs and identifies potentially suspicious login behavior.

The analyzer currently:

- Counts failed login attempts by IP address
- Identifies IP addresses with repeated failed logins
- Extracts usernames associated with login activity
- Detects successful logins following repeated failures
- Generates a readable security analysis report

## Detection Logic

The current detection threshold is 3 failed login attempts.

An IP address is flagged when it produces 3 or more failed login attempts.

The tool also generates a warning when a successful login occurs after repeated failed attempts from the same IP address and username.

## Example Finding

A simulated log may contain:

    LOGIN_FAILED
    LOGIN_FAILED
    LOGIN_FAILED
    LOGIN_FAILED
    LOGIN_SUCCESS

The analyzer will flag this activity for further investigation.

This does not automatically prove that an attack occurred. Legitimate users can also generate repeated failed login attempts.

## Technologies

- Python 3
- Termux
- Git
- GitHub

## How to Run

Clone the repository:

    git clone <repository-url>

Enter the project directory:

    cd log-analyzer

Run the analyzer:

    python analyzer.py

## Project Structure

    log-analyzer/
    ├── analyzer.py
    ├── auth.log
    └── README.md

## Future Improvements

Planned improvements include:

- Detecting multiple suspicious patterns
- Generating reports automatically
- Supporting larger log files
- Adding command-line arguments
- Detecting unusual login times
- Exporting findings to CSV
- Adding automated tests

## Disclaimer

This project is intended for educational and defensive security analysis.

The included authentication log contains simulated data.
