from features.encoder import dict_to_vector

def train_random_forest(X, y):
    X_vec = [dict_to_vector(x) for x in X]

    from sklearn.ensemble import RandomForestClassifier
    model = RandomForestClassifier()

    model.fit(X_vec, y)
    return model