import json
from pathlib import Path
from app.database import SessionLocal, DBAlert

LOG_PATH = Path("suricata_logs/eve.json")

def map_to_mitre(signature: str):
    sig_lower = signature.lower()
    if "sql" in sig_lower or "injection" in sig_lower:
        return {"tactic": "Initial Access", "technique_id": "T1190"}
    elif "brute" in sig_lower or "login" in sig_lower or "auth" in sig_lower:
        return {"tactic": "Credential Access", "technique_id": "T1110"}
    elif "scan" in sig_lower or "nmap" in sig_lower:
        return {"tactic": "Discovery", "technique_id": "T1046"}
    elif "malware" in sig_lower or "trojan" in sig_lower or "backdoor" in sig_lower:
        return {"tactic": "Command and Control", "technique_id": "T1071"}
    else:
        return {"tactic": "Execution", "technique_id": "T1204"}

def get_latest_suricata_alerts(limit=50):
    db = SessionLocal()
    try:
        # Check if we have records in DB, otherwise ingest from eve.json
        db_alerts = db.query(DBAlert).order_by(DBAlert.timestamp.desc()).limit(limit).all()
        if db_alerts:
            alerts = []
            for a in db_alerts:
                alerts.append({
                    "id": a.id,
                    "timestamp": a.timestamp,
                    "src_ip": a.src_ip,
                    "dest_ip": a.dest_ip,
                    "severity": a.severity,
                    "signature": a.signature,
                    "mitre": {"tactic": a.tactic, "technique_id": a.technique_id}
                })
            return alerts
            
        # Fallback to parsing eve.json and saving to DB
        if not LOG_PATH.exists():
            return []
            
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
                    alert_id = data.get("flow_id", str(len(alerts) + 1))
                    
                    # Save to DB
                    db_alert = DBAlert(
                        id=alert_id,
                        timestamp=data.get("timestamp"),
                        src_ip=data.get("src_ip"),
                        dest_ip=data.get("dest_ip"),
                        severity=alert_data.get("severity", 3),
                        signature=sig,
                        tactic=mitre.get("tactic"),
                        technique_id=mitre.get("technique_id")
                    )
                    db.merge(db_alert)
                    
            db.commit()
            
        # Re-query from DB
        db_alerts = db.query(DBAlert).order_by(DBAlert.timestamp.desc()).limit(limit).all()
        return [{
            "id": a.id, "timestamp": a.timestamp, "src_ip": a.src_ip, "dest_ip": a.dest_ip,
            "severity": a.severity, "signature": a.signature,
            "mitre": {"tactic": a.tactic, "technique_id": a.technique_id}
        } for a in db_alerts]
        
    except Exception as e:
        print(f"Error in alert service: {e}")
        return []
    finally:
        db.close()
