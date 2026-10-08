from scapy.all import sniff
from feature_extraction import extract_features
from intrusion_detector import IntrusionDetector
import csv
import sys
import os

# Allow importing database.py from project root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import create_database, save_packet


# Create database
create_database()


# Load real normal traffic data
normal_data = []

with open("data/normal_traffic.csv", "r") as file:

    reader = csv.DictReader(file)

    for row in reader:

        normal_data.append([
            float(row["packet_length"]),
            float(row["protocol"]),
            float(row["source_port"]),
            float(row["destination_port"])
        ])


# Create AI detector
detector = IntrusionDetector()

# Train using real network traffic
detector.train(normal_data)


def process_packet(packet):

    features = extract_features(packet)

    # Ignore non-IP packets
    if features["protocol"] == "Unknown":
        return

    protocol = features["protocol"]

    ml_features = [
        features["packet_length"],
        protocol,
        features["source_port"],
        features["destination_port"]
    ]

    # AI prediction
    result = detector.predict(ml_features)

    print("\n==============================")
    print("        PACKET ANALYSIS")
    print("==============================")

    print("Source IP       :", features["source_ip"])
    print("Destination IP  :", features["destination_ip"])
    print("Protocol        :", features["protocol"])
    print("Source Port     :", features["source_port"])
    print("Destination Port:", features["destination_port"])
    print("Packet Length   :", features["packet_length"])
    print("Anomaly Result  :", result)

    # Calculate anomaly score for database
    import numpy as np

    data = np.array(ml_features, dtype=float)

    z_scores = np.abs(
        (data - detector.mean) / detector.std
    )

    anomaly_score = float(np.mean(z_scores))

    print("Anomaly Score   :", round(anomaly_score, 2))

    # Save packet information
    save_packet(
        features["source_ip"],
        features["destination_ip"],
        features["protocol"],
        features["source_port"],
        features["destination_port"],
        features["packet_length"],
        anomaly_score,
        result
    )

    print("✓ Packet saved to database.")

    if result == "ATTACK":

        print("⚠️ ALERT: Suspicious traffic detected!")

    else:

        print("✓ Traffic appears normal.")

print("\nStarting Adaptive IDS...")
print("LIVE MONITORING STARTED")
print("Capturing network traffic continuously...")
print("Press CTRL+C to stop.\n")

sniff(
    prn=process_packet
)


