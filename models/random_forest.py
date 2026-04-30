from sklearn.ensemble import RandomForestClassifier

class RFModel:
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=150,
            max_depth=20,
            class_weight={
                0: 2.0,  # instagram
                1: 3.0,  # spotify (kritikus!)
                2: 1.0,  # youtube
                3: 2.0,  # tiktok
                4: 1.5   # whatsapp
            },
            random_state=42
        )
        
    def train(self, X, y):
        self.model.fit(X, y)

    def predict(self, X):
        return self.model.predict(X)