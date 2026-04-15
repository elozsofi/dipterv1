from utils import load_dataset
from sklearn.model_selection import train_test_split

from models.random_forest import train_random_forest
from evaluation.metrics import evaluate_model


def main():
    print("Loading dataset...")
    X, y = load_dataset()

    print(f"Loaded {len(X)} samples")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )

    print("Training Random Forest...")
    model = train_random_forest(X_train, y_train)

    print("Evaluating...")
    evaluate_model(model, X_test, y_test)


if __name__ == "__main__":
    main()