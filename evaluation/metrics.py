from sklearn.metrics import accuracy_score, classification_report

def evaluate_model(model, X_test, y_test):
    from features.encoder import dict_to_vector

    X_vec = [dict_to_vector(x) for x in X_test]
    y_pred = model.predict(X_vec)

    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification report:\n")
    print(classification_report(y_test, y_pred))