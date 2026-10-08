import numpy as np


class IntrusionDetector:

    def __init__(self):
        self.mean = None
        self.std = None

    def train(self, normal_data):

        data = np.array(normal_data, dtype=float)

        self.mean = np.mean(data, axis=0)
        self.std = np.std(data, axis=0)

        # Prevent division by zero
        self.std[self.std == 0] = 1

        print("AI anomaly detector trained successfully.")

    def predict(self, features):

        data = np.array(features, dtype=float)

        # Calculate how unusual each feature is
        z_scores = np.abs((data - self.mean) / self.std)

        # Overall anomaly score
        anomaly_score = np.mean(z_scores)

        print("Anomaly Score:", round(anomaly_score, 2))

        if anomaly_score > 3:
            return "ATTACK"
        else:
            return "NORMAL"