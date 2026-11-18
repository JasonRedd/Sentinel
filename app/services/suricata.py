import json
from pathlib import Path

LOG_PATH = Path("suricata_logs/eve.json")

def map_to_mitre(signature: str):
    sig_lower = signature.lower()
    if "sql" in sig_lower or "injection" in sig_lower:
        return {"tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"}
    elif "brute" in sig_lower or "login" in sig_lower or "auth" in sig_lower:
        return {"tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force"}
    elif "scan" in sig_lower or "nmap" in sig_lower:
        return {"tactic": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Discovery"}
    elif "malware" in sig_lower or "trojan" in sig_lower or "backdoor" in sig_lower:
        return {"tactic": "Command and Control", "technique_id": "T1071", "technique_name": "Application Layer Protocol"}
    else:
        return {"tactic": "Execution", "technique_id": "T1204", "technique_name": "User Execution"}

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
                    sig = alert_data.get("signature", "Unknown Signature")
                    mitre = map_to_mitre(sig)
                    alerts.append({
                        "id": data.get("flow_id", str(len(alerts) + 1)),
                        "timestamp": data.get("timestamp"),
                        "src_ip": data.get("src_ip"),
                        "dest_ip": data.get("dest_ip"),
                        "severity": alert_data.get("severity", 3),
                        "signature": sig,
                        "mitre": mitre
                    })
                if len(alerts) >= limit:
                    break
    except Exception as e:
        print(f"Error reading Suricata logs: {e}")
        
    return alerts
