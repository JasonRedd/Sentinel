import json
from pathlib import Path

LOG_PATH = Path("suricata_logs/eve.json")

def get_latest_suricata_alerts(limit=50):
    alerts = []
    if not LOG_PATH.exists():
        return []
    
    try:
        with open(LOG_PATH, "r") as f:
            lines = f.readlines()
            for line in reversed(lines):
                if not line.strip():
                    continue
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    alert_data = data.get("alert", {})
                    alerts.append({
                        "id": data.get("flow_id", str(len(alerts) + 1)),
                        "timestamp": data.get("timestamp"),
                        "src_ip": data.get("src_ip"),
                        "dest_ip": data.get("dest_ip"),
                        "severity": alert_data.get("severity", 3),
                        "signature": alert_data.get("signature", "Unknown Signature")
                    })
                if len(alerts) >= limit:
                    break
    except Exception as e:
        print(f"Error reading Suricata logs: {e}")
        
    return alerts
