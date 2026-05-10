# rule-based + ML
from models.rule_based import classify as rule_classify

class HybridModel:

    def __init__(self, ml_model):
        self.ml_model = ml_model

    def predict(self, X_f, X_full):

        preds = []

        for i, x_f in enumerate(X_f):

            service, flow_id = X_full[i]

            # Rule result
            rule_result = rule_classify(service, flow_id)

            rule_pred = rule_result["prediction"]
            rule_conf = rule_result["confidence"]

            # RF prediction
            rf_pred = self.ml_model.predict([x_f])[0]

            # RF probabilities
            rf_probs = self.ml_model.model.predict_proba([x_f])[0]

            rf_conf = max(rf_probs) * 10

            # =====================================================
            # Weighted decision
            # =====================================================

            # Strong rule wins
            if rule_conf >= 8:
                preds.append(rule_pred)
                continue

            # RF clearly confident
            if rf_conf >= 8:
                preds.append(rf_pred)
                continue

            # Agreement
            if rule_pred == rf_pred:
                preds.append(rf_pred)
                continue

            # Compare confidence
            if rule_conf > rf_conf:
                preds.append(rule_pred)
            else:
                preds.append(rf_pred)

        return preds