import re
from typing import List, Dict


# --- Regex patterns for demonstration (heuristic, not complete security checks) ---

SQL_INJECTION_PATTERNS = [
    # Concatenating user input into SQL string, very simple heuristic
    re.compile(
        r"(SELECT|UPDATE|DELETE|INSERT)\s+.+\s+(FROM|INTO)\s+.+\+.+",
        re.IGNORECASE,
    ),
    # Using format or f-string with SQL keywords
    re.compile(
        r"(SELECT|UPDATE|DELETE|INSERT).*(%s|\{.*\})",
        re.IGNORECASE,
    ),
]

HARDCODED_CREDENTIAL_PATTERNS = [
    # simple passwords, api keys variables
    re.compile(
        r"(password|passwd|pwd|secret|token|api_key)\s*=\s*['\"].+['\"]",
        re.IGNORECASE,
    ),
    # AWS style access key id
    re.compile(r"AKIA[0-9A-Z]{16}"),
]

UNSAFE_EVAL_PATTERNS = [
    # direct eval or exec usage
    re.compile(r"\beval\("),
    re.compile(r"\bexec\("),
]


def _scan_patterns(
    lines: List[str], patterns: List[re.Pattern], rule_name: str
) -> List[Dict]:
    findings: List[Dict] = []
    for idx, line in enumerate(lines, start=1):
        for pattern in patterns:
            if pattern.search(line):
                findings.append(
                    {
                        "rule": rule_name,
                        "line": idx,
                        "snippet": line.strip(),
                        "pattern": pattern.pattern,
                    }
                )
    return findings


def analyze_code_static(code: str) -> List[Dict]:
    """
    Run simple regex-based static analysis.
    Returns a list of findings, each a dict with:
      - rule
      - line
      - snippet
      - pattern
    """
    lines = code.splitlines()

    findings: List[Dict] = []
    findings.extend(_scan_patterns(lines, SQL_INJECTION_PATTERNS, "SQL_INJECTION"))
    findings.extend(
        _scan_patterns(lines, HARDCODED_CREDENTIAL_PATTERNS, "HARDCODED_CREDENTIAL")
    )
    findings.extend(_scan_patterns(lines, UNSAFE_EVAL_PATTERNS, "UNSAFE_EVAL"))

    return findings


