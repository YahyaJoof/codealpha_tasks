# CodeAlpha Secure Coding Review

## Project Overview

This project was completed as part of the **CodeAlpha Cyber Security Internship**.

The objective of this project is to perform a security review of a Python Flask application, identify security vulnerabilities, and implement secure coding improvements.

The project contains two versions of the application:

- `vulnerable_app.py` — intentionally vulnerable version used for security analysis.
- `secure_app.py` — corrected version containing security improvements.

The application was tested locally using `127.0.0.1` and was not deployed against any third-party system.

---

## Objectives

The main objectives of this project were to:

1. Review application source code for security vulnerabilities.
2. Identify insecure coding practices.
3. Use a static security analysis tool to detect vulnerabilities.
4. Assess the potential impact of identified vulnerabilities.
5. Implement secure coding improvements.
6. Re-scan the corrected application to verify the improvements.
7. Document the findings and remediation process.

---

## Technologies Used

- Python
- Flask
- SQLite
- Bandit
- Werkzeug Security
- VS Code
- Windows

---

## Project Structure

```text
CodeAlpha_SecureCodingReview/
│
├── vulnerable_app.py
├── secure_app.py
├── security_review.md
├── requirements.txt
├── users.db
├── users_secure.db
│
└── screenshots/
    ├── 01_application_running.png
    ├── 02_bandit_high_1.png
    ├── 02_bandit_vulnerable_1.png
    ├── 03_vulnerable_code_1.png
    ├── 03_vulnerable_code_2.png
    ├── 03_vulnerable_code_3.png
    ├── 05_bandit_secure.png
    ├── 06_secure_application.png
    └── B201flask_debug_true.png