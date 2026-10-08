from intrusion_detector import IntrusionDetector


# Normal network traffic samples
normal_data = [
    [80, 17, 5353, 5353],
    [82, 17, 5353, 5353],
    [100, 17, 5353, 5353],
    [90, 17, 5353, 5353],
    [75, 17, 5353, 5353],
    [85, 6, 443, 52000],
    [95, 6, 443, 52001],
    [100, 6, 443, 52002],
    [88, 6, 443, 52003],
    [92, 6, 443, 52004]
]


detector = IntrusionDetector()

detector.train(normal_data)


# Test normal traffic
normal_packet = [85, 17, 5353, 5353]

result = detector.predict(normal_packet)

print("\nNormal packet result:", result)


# Test unusual traffic
suspicious_packet = [65000, 9999, 1, 65535]

result = detector.predict(suspicious_packet)

print("Suspicious packet result:", result)