import os
import threading
from typing import Dict, Any

import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, "models", "code_vuln_model.joblib")

_MODEL = None
_MODEL_LOCK = threading.Lock()


def load_model() -> Any:
    """
    Load the trained TF-IDF + Logistic Regression pipeline.
    Uses a simple in-memory singleton with a thread lock.
    """
    global _MODEL
    with _MODEL_LOCK:
        if _MODEL is None:
            model_path = os.getenv("ML_MODEL_PATH", DEFAULT_MODEL_PATH)
            if not os.path.exists(model_path):
                raise FileNotFoundError(
                    f"ML model not found at {model_path}. "
                    f"Run train_model.py first to train and save the model."
                )
            _MODEL = joblib.load(model_path)
    return _MODEL


def predict_vulnerability(code: str, threshold: float = 0.5) -> Dict[str, Any]:
    """
    Predict vulnerability likelihood for a given code string.
    Returns:
        {
            'label': 'vulnerable' or 'safe',
            'probability': float between 0 and 1,
        }

    Note: This is a statistical classifier trained on labeled examples.
    It supports human reviewers and does not guarantee detection of all vulnerabilities.
    """
    model = load_model()
    proba = model.predict_proba([code])[0][1]  # probability of class '1' (vulnerable)
    label = "vulnerable" if proba >= threshold else "safe"
    return {"label": label, "probability": float(proba)}


