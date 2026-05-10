from sklearn.ensemble import RandomForestClassifier

class RFModel:

    def __init__(self):

        self.model = RandomForestClassifier(

            # Forest size
            n_estimators=300,

            # Prevent overfitting
            max_depth=12,

            # Better generalization
            min_samples_split=4,
            min_samples_leaf=2,

            # Random feature subset
            max_features="sqrt",

            # Handle imbalance
            class_weight={
                0: 2.0,   # instagram
                1: 3.0,   # spotify
                2: 1.0,   # youtube
                3: 2.0,   # tiktok
                4: 1.5    # whatsapp
            },

            # Use OOB estimate
            oob_score=True,

            # Parallelize
            n_jobs=-1,

            random_state=42
        )

    def train(self, X, y):
        self.model.fit(X, y)

        print(f"[RF] OOB score: {self.model.oob_score_:.4f}")

    def predict(self, X):
        return self.model.predict(X)

    def predict_proba(self, X):
        return self.model.predict_proba(X)