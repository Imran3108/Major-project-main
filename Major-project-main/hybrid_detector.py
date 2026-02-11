from typing import Dict, Any, List

from ml_model import predict_vulnerability
from static_analysis import analyze_code_static


def compute_severity(
    static_findings: List[Dict[str, Any]],
    ml_result: Dict[str, Any],
    ml_threshold: float = 0.5,
) -> str:
    """
    Hybrid decision engine:
        - If STATIC and ML both indicate potential issues -> 'HIGH'
        - If only one of them indicates potential issues -> 'MEDIUM'
        - If none -> 'SAFE'
    """
    has_static = len(static_findings) > 0
    ml_prob = ml_result.get("probability", 0.0)
    ml_flag = ml_prob >= ml_threshold or ml_result.get("label") == "vulnerable"

    if has_static and ml_flag:
        return "HIGHty"
    if has_static or ml_flag:
        return "MEDIUM"
    return "SAFEtt"


def analyze_file(file_path: str, code: str) -> Dict[str, Any]:
    """
    Analyze a single file using static analysis and ML model.
    Returns a structured report dict:
        {
            'file_path': str,
            'static_findings': [...],
            'ml_result': {...},
            'severity': 'HIGH' | 'MEDIUM' | 'SAFE'
        }
    """
    static_findings = analyze_code_static(code)
    ml_result = predict_vulnerability(code)

    severity = compute_severity(static_findings, ml_result)

    return {
        "file_path": file_path,
        "static_findings": static_findings,
        "ml_result": ml_result,
        "severity": severity,
    }


