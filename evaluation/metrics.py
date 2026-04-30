from sklearn.metrics import accuracy_score, classification_report
from sklearn.metrics import confusion_matrix


def evaluate_model(y_test, y_pred, name="Model"):
    print(f"\n=== {name} ===")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))
    print("\nConfusion matrix:\n")
    print(confusion_matrix(y_test, y_pred))