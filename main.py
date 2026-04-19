from utils import load_dataset
from sklearn.model_selection import train_test_split

from models.random_forest import train_random_forest
from models.svm import train_svm
from evaluation.metrics import evaluate_model
from models.rule_based import classify_rule_based


def evaluate_rule_based(X_test, y_test):
    y_pred = []

    for features in X_test:
        y_pred.append(classify_rule_based(features))

    from sklearn.metrics import accuracy_score
    print("Accuracy:", accuracy_score(y_test, y_pred))


def main():
    print("Loading dataset...")
    X, y = load_dataset()
    print(f"Loaded {len(X)} samples")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # Random Forest
    print("\n=== Random Forest ===")
    rf_model = train_random_forest(X_train, y_train)
    evaluate_model(rf_model, X_test, y_test)

    # SVM
    print("\n=== SVM ===")
    svm_model = train_svm(X_train, y_train)
    evaluate_model(svm_model, X_test, y_test)

    # Rule-based
    print("\n=== Rule-based ===")
    evaluate_rule_based(X_test, y_test)


if __name__ == "__main__":
    main()