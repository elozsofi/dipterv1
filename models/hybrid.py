# rule-based + ML
from models.rule_based import classify as rule_classify

class HybridModel:
    def __init__(self, ml_model):
        self.ml_model = ml_model

    def predict(self, X_f, X_full):
        preds = []

        for i, x_f in enumerate(X_f):
            service, flow_id = X_full[i]
            rule_pred = rule_classify(service, flow_id)
            rf_pred = self.ml_model.predict([x_f])[0]

            # Ensemble: if both agree, use it; otherwise, use RF (more general)
            if rule_pred == rf_pred:
                preds.append(rule_pred)
            else:
                preds.append(rf_pred)

        return preds