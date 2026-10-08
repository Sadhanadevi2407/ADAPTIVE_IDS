from scapy.all import IP, IPv6, TCP, UDP


def extract_features(packet):

    features = {
        "source_ip": "Unknown",
        "destination_ip": "Unknown",
        "protocol": "Unknown",
        "source_port": 0,
        "destination_port": 0,
        "packet_length": len(packet)
    }

    # IPv4
    if packet.haslayer(IP):
        features["source_ip"] = packet[IP].src
        features["destination_ip"] = packet[IP].dst
        features["protocol"] = packet[IP].proto

    # IPv6
    elif packet.haslayer(IPv6):
        features["source_ip"] = packet[IPv6].src
        features["destination_ip"] = packet[IPv6].dst
        features["protocol"] = packet[IPv6].nh

    # TCP
    if packet.haslayer(TCP):
        features["source_port"] = packet[TCP].sport
        features["destination_port"] = packet[TCP].dport

    # UDP
    elif packet.haslayer(UDP):
        features["source_port"] = packet[UDP].sport
        features["destination_port"] = packet[UDP].dport

    return features