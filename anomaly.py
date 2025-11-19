# modules/anomaly.py
from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np

def detection_on_numeric(df, numeric_cols, contamination=0.02):
    """
    numeric_cols: list of columns to use for anomaly detection.
    Returns df with _anomaly_score and _is_anomaly boolean.
    """
    df2 = df.copy()
    # Prepare numeric matrix
    X = df2[numeric_cols].apply(pd.to_numeric, errors="coerce").fillna(0).values
    if X.shape[0] < 5:
        df2["_anomaly_score"] = 0
        df2["_is_anomaly"] = False
        return df2
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(X)
    scores = model.decision_function(X)  # higher -> more normal
    preds = model.predict(X)             # -1 anomaly, 1 normal
    # convert to 0..1 score where low is anomaly
    df2["_anomaly_score"] = (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)
    df2["_is_anomaly"] = preds == -1
    return df2
