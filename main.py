from data_loader import build_dataset
from models.random_forest import RFModel
from models.svm import SVMModel
from evaluation.metrics import evaluate_model as evaluate
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from models.hybrid import HybridModel
from models.rule_based import classify as rule_classify
import numpy as np

def main():
    X_features, X_full, y = build_dataset("data")

    X_train_f, X_test_f, X_train_full, X_test_full, y_train, y_test = train_test_split(
        X_features, X_full, y, test_size=0.2, random_state=42
    )

    scaler = StandardScaler()
    X_train_f = scaler.fit_transform(X_train_f)
    X_test_f = scaler.transform(X_test_f)

    rf = RFModel()
    rf.train(X_train_f, y_train)

    # Rule-based evaluation
    rule_preds = []
    for service, flow_id in X_test_full:
        result = rule_classify(service, flow_id)
        pred = result["prediction"]
        rule_preds.append(pred)
    evaluate(y_test, rule_preds, "Rule-based")

    hybrid = HybridModel(rf)
    hybrid_preds = hybrid.predict(X_test_f, X_test_full)
    evaluate(y_test, hybrid_preds, "Hybrid (Rule + RF)")

    preds = rf.predict(X_test_f)
    evaluate(y_test, preds, "Random Forest")

    svm = SVMModel()
    svm.train(X_train_f, y_train)

    preds = svm.predict(X_test_f)
    evaluate(y_test, preds, "SVM")
    
    print("\nFeature importance (RF):")
    for i, imp in enumerate(rf.model.feature_importances_):
        print(f"Feature {i}: {imp:.4f}")


if __name__ == "__main__":
    main()