from data_loader import build_dataset
from models.random_forest import RFModel
from models.svm import SVMModel
from evaluation.metrics import evaluate_model as evaluate
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from models.hybrid import HybridModel
import numpy as np

def main():
    X, y = build_dataset("data")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    rf = RFModel()
    rf.train(X_train, y_train)

    hybrid = HybridModel(rf)
    hybrid_preds = hybrid.predict(X_test)
    evaluate(y_test, hybrid_preds, "Hybrid (Rule + RF)")

    preds = rf.predict(X_test)
    evaluate(y_test, preds, "Random Forest")

    svm = SVMModel()
    svm.train(X_train, y_train)

    preds = svm.predict(X_test)
    evaluate(y_test, preds, "SVM")
    
    print("\nFeature importance (RF):")
    for i, imp in enumerate(rf.model.feature_importances_):
        print(f"Feature {i}: {imp:.4f}")


if __name__ == "__main__":
    main()