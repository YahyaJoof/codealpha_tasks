# CodeAlpha Secure Coding Review

## 1. Project Overview

This project is a secure coding review of a Python Flask application developed for the CodeAlpha Cyber Security Internship.

The original application (`vulnerable_app.py`) was reviewed using manual code inspection and the Bandit security scanner. Several security weaknesses were identified and documented.

A corrected version (`secure_app.py`) was then developed to address the identified vulnerabilities.

---

## 2. Security Assessment

### Vulnerability 1: Hardcoded Secret

**Location:** `vulnerable_app.py`

```python
app.config["SECRET_KEY"] = "CodeAlphaSuperSecret123"