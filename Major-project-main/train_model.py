import os
import csv
from typing import List, Tuple

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "code_vuln_model.joblib")


def load_dataset(path: str) -> Tuple[List[str], List[int]]:
    """
    Load dataset from CSV.
    - column 'label': 'safe' or 'vulnerable'
    - column 'code': code snippet
    Returns X (list of code strings) and y (0/1).
    """
    X: List[str] = []
    y: List[int] = []

    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            label_str = row["label"].strip().lower()
            code = row["code"]
            if not code:
                continue
            if label_str not in {"safe", "vulnerable"}:
                continue
            label_int = 1 if label_str == "vulnerable" else 0
            X.append(code)
            y.append(label_int)

    if not X:
        raise ValueError("Dataset is empty or invalid. Please check dataset.csv.")
    return X, y


def build_pipeline() -> Pipeline:
    """
    Build a simple TF-IDF + Logistic Regression pipeline.
    This is a lightweight text classifier used only as a decision-support signal.
    """
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=1,
    )
    classifier = LogisticRegression(max_iter=1000)
    pipeline = Pipeline(
        [
            ("tfidf", vectorizer),
            ("clf", classifier),
        ]
    )
    return pipeline


def main() -> None:
    print("[train_model] Loading dataset from", DATASET_PATH)
    X, y = load_dataset(DATASET_PATH)

    print(f"[train_model] Loaded {len(X)} samples.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = build_pipeline()
    print("[train_model] Training model...")
    model.fit(X_train, y_train)

    print("[train_model] Evaluating on test set...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[train_model] Accuracy: {acc:.3f}")
    print("[train_model] Classification report:")
    print(classification_report(y_test, y_pred, target_names=["safe", "vulnerable"]))

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"[train_model] Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()


