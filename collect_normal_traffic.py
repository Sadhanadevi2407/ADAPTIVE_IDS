from scapy.all import sniff
from feature_extraction import extract_features
import csv


OUTPUT_FILE = "data/normal_traffic.csv"


def process_packet(packet):

    features = extract_features(packet)

    protocol = features["protocol"]

    if not isinstance(protocol, int):
        protocol = 0

    return [
        features["packet_length"],
        protocol,
        features["source_port"],
        features["destination_port"]
    ]


print("Collecting normal network traffic...")
print("Capture 100 packets while using your computer normally.")

packets = sniff(count=100)

with open(OUTPUT_FILE, "w", newline="") as file:

    writer = csv.writer(file)

    writer.writerow([
        "packet_length",
        "protocol",
        "source_port",
        "destination_port"
    ])

    for packet in packets:

        data = process_packet(packet)

        writer.writerow(data)

print("\nNormal traffic dataset created!")
print("Saved to:", OUTPUT_FILE)