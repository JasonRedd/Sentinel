import random

def score_traffic_vector(features: list):
    """
    Simulates or computes Isolation Forest anomaly scoring with XAI feature attribution.
    Features format expected: [bytes_sent, packet_rate, port_num]
    """
    if len(features) < 3:
        features = [1000.0, 50.0, 80.0]
        
    bytes_sent, packet_rate, port_num = features[0], features[1], features[2]
    
    # Simple heuristic threshold for anomaly demonstration
    is_anomaly = bytes_sent > 50000 or packet_rate > 800 or port_num == 3389
    score = -0.75 if is_anomaly else 0.15
    
    # Explainable AI (XAI) feature attribution breakdown
    attributions = []
    if bytes_sent > 50000:
        attributions.append(f"Abnormally high payload volume ({bytes_sent} bytes) indicating potential data exfiltration.")
    if packet_rate > 800:
        attributions.append(f"High packet frequency ({packet_rate} pkts/sec) suggesting scanning or volumetric activity.")
    if port_num == 3389:
        attributions.append("Traffic targeted to sensitive RDP management port (3389).")
        
    if not attributions:
        attributions.append("All network behavioral metrics fall within standard baseline parameters.")

    return {
        "anomaly": bool(is_anomaly),
        "score": float(score),
        "explanation": attributions
    }
