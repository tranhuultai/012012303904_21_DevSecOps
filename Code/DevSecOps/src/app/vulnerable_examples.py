# Cố ý tạo lỗi
"""
INTENTIONALLY VULNERABLE CODE
--------------------------------
This file exists only for the DevSecOps security scanning experiment.

DO NOT use these examples in a production application.
"""

import os
import subprocess


# ---------------------------------------------------------
# VUL-01: Hardcoded secret
# Expected detector: Gitleaks
# ---------------------------------------------------------

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "EXAMPLE_SECRET_ONLY_FOR_SECURITY_TESTING"


# ---------------------------------------------------------
# VUL-02: Command injection
# Expected detector: Semgrep
# ---------------------------------------------------------

def run_command(user_input: str) -> str:
    """
    Intentionally unsafe example.

    DO NOT use shell=True with untrusted user input.
    """
    result = subprocess.check_output(
        user_input,
        shell=True,
        text=True,
    )

    return result


# ---------------------------------------------------------
# VUL-03: Use of environment secret without validation
# This is included as a test fixture for secret handling.
# ---------------------------------------------------------

def get_api_key():
    api_key = os.getenv("API_KEY")

    return api_key


# ---------------------------------------------------------
# VUL-04: Unsafe dynamic evaluation
# Expected detector: Semgrep
# ---------------------------------------------------------

def calculate_expression(expression: str):
    """
    Intentionally unsafe example.
    """
    return eval(expression)