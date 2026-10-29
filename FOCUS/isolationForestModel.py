import os
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

FEATURE_NAMES = [
    'inbound_data',
    'outbound_data',
    'total_data',
    'traffic_ratio',
]

def extract_features_df(df: pd.DataFrame, epsilon: float = 1e-4) -> pd.DataFrame:
    """
    Extracts fixed deterministic features for Isolation Forest.
    Features:
    - inbound_data: inbound traffic speed (Mbps)
    - outbound_data: outbound traffic speed (Mbps)
    - total_data: inbound_data + outbound_data
    - traffic_ratio: inbound_data / max(outbound_data, epsilon)
    """
    inbound = df['inbound_data'].astype(float)
    outbound = df['outbound_data'].astype(float)
    total = inbound + outbound
    ratio = inbound / outbound.clip(lower=epsilon)
    
    features = pd.DataFrame({
        'inbound_data': inbound,
        'outbound_data': outbound,
        'total_data': total,
        'traffic_ratio': ratio,
    }, columns=FEATURE_NAMES)
    return features

def extract_single_feature_vector(inbound: float, outbound: float, epsilon: float = 1e-4) -> pd.DataFrame:
    """
    Creates a single-row DataFrame with identical feature ordering for inference.
    """
    total = float(inbound) + float(outbound)
    ratio = float(inbound) / max(float(outbound), epsilon)
    
    return pd.DataFrame([[float(inbound), float(outbound), total, ratio]], columns=FEATURE_NAMES)

def train_isolation_forest(
    csv_path: str = 'network_data_log.csv',
    model_output_path: str = 'isolationForestModel.joblib',
    contamination: float = 0.05,
    random_state: int = 42
):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Training data not found at {csv_path}")

    data = pd.read_csv(csv_path)
    required_cols = {'inbound_data', 'outbound_data'}
    if not required_cols.issubset(set(data.columns)):
        raise ValueError(f"CSV must contain columns: {required_cols}. Found: {list(data.columns)}")

    features = extract_features_df(data)
    print(f"Loaded {len(features)} records from {csv_path}")
    print(f"Training IsolationForest with features: {FEATURE_NAMES}")

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state
    )
    model.fit(features)

    joblib.dump(model, model_output_path)
    print(f"Model saved successfully to {model_output_path}")
    return model

if __name__ == '__main__':
    train_isolation_forest()
