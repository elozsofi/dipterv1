from sklearn.svm import SVC


def train_svm(X_train, y_train):
    model = SVC()
    model.fit(X_train, y_train)
    return model