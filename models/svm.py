from sklearn.svm import SVC

class SVMModel:
    def __init__(self):
        self.model = SVC(
            kernel="rbf",
            C=10,
            gamma="scale"
        )

    def train(self, X, y):
        self.model.fit(X, y)

    def predict(self, X):
        return self.model.predict(X)