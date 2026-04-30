# rule-based + ML

from models.rule_based import classify as rule_classify


class HybridModel:
    def __init__(self, ml_model):
        self.ml_model = ml_model

    def predict(self, X):
        preds = []

        for x in X:
            rule_pred = rule_classify(x)

            if rule_pred != -1:
                preds.append(rule_pred)
            else:
                preds.append(self.rf.predict([x])[0])

        return preds