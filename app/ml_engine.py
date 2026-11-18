import numpy as np
from sklearn.ensemble import IsolationForest

class NetworkAnomalyDetector:
    def __init__(self):
        # Isolation Forest for unsupervised anomaly detection
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.is_trained = False

    def train(self, historical_data):
        # Expects a list of feature vectors: [packet_size, connection_frequency, port_index]
        if len(historical_data) < 10:
            return False
        X = np.array(historical_data)
        self.model.fit(X)
        self.is_trained = True
        return True

    def predict(self, feature_vector):
        if not self.is_trained:
            return 0  # Default to normal if untrained
        X = np.array([feature_vector])
        # IsolationForest returns -1 for anomalies and 1 for normal
        prediction = self.model.predict(X)[0]
        return -1 if prediction == -1 else 1

# Global anomaly detector instance
anomaly_detector = NetworkAnomalyDetector()
