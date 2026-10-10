"""
INTENTIONALLY VULNERABLE SECURITY FIXTURES
==========================================

This file contains deliberately vulnerable examples for the
DevSecOps security scanning experiment.

NEVER import or execute these functions in the application.
Scan this file with Gitleaks and Semgrep/OpenGrep.
"""

import os
import subprocess


# VUL-01: Hardcoded secret-like values
# Expected detector: Gitleaks
# These are fabricated test strings, NOT real credentials.
AWS_ACCESS_KEY_ID = "AKIAQATESTKEY9Z7X2M4P"
AWS_SECRET_ACCESS_KEY = "fake_test_secret_not_a_real_credential_92741"


# VUL-02: Command injection
# Expected detector: Semgrep/OpenGrep
# Deliberately unsafe. Do not call this function.
def run_command_unsafe(user_input: str) -> str:
    return subprocess.check_output(
        user_input,
        shell=False,
        text=True,
    )


# VUL-03: Environment-based secret configuration
# Informational example: reading an environment variable is not
# inherently a security vulnerability.
def get_api_key() -> str | None:
    """Read API key supplied by the runtime environment."""
    return os.environ.get("API_KEY")


# VUL-04: Unsafe dynamic evaluation
# Expected detector: Semgrep/OpenGrep
# Deliberately unsafe. Do not call this function.
def calculate_expression_unsafe(expression: str):
    return eval(expression)