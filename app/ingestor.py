import os
import json
import time
import redis

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
EVE_LOG_PATH = "./suricata_logs/eve.json"

client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def tail_suricata_logs():
    print(f"[*] Starting SENTINEL Ingestor, watching {EVE_LOG_PATH}...")
    while not os.path.exists(EVE_LOG_PATH):
        print("[*] Waiting for Suricata eve.json log file to be generated...")
        time.sleep(2)
    with open(EVE_LOG_PATH, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                event = json.loads(line.strip())
                if event.get("event_type") == "alert":
                    alert_data = {
                        "timestamp": event.get("timestamp"),
                        "src_ip": event.get("src_ip", "unknown"),
                        "dest_ip": event.get("dest_ip", "unknown"),
                        "signature": event.get("alert", {}).get("signature", "Unknown Signature"),
                        "severity": str(event.get("alert", {}).get("severity", 3)),
                        "category": event.get("alert", {}).get("category", "General")
                    }
                    client.xadd("sentinel:alerts", alert_data)
                    print(f"[+] Alert Ingested: {alert_data[\"signature\"]} from {alert_data[\"src_ip\"]}")
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"[!] Ingestion error: {e}")

if __name__ == "__main__":
    tail_suricata_logs()
