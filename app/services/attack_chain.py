from app.services.suricata import get_latest_suricata_alerts

def reconstruct_attack_chains():
    """
    Correlates individual Suricata alerts by source IP into chronological attack chains / kill chains.
    """
    alerts = get_latest_suricata_alerts(limit=100)
    chains = {}
    
    for alert in alerts:
        src_ip = alert.get("src_ip")
        if not src_ip:
            continue
            
        if src_ip not in chains:
            chains[src_ip] = {
                "source_ip": src_ip,
                "total_events": 0,
                "tactics_observed": set(),
                "timeline": []
            }
            
        chains[src_ip]["total_events"] += 1
        mitre = alert.get("mitre", {})
        tactic = mitre.get("tactic", "Unknown")
        chains[src_ip]["tactics_observed"].add(tactic)
        
        chains[src_ip]["timeline"].append({
            "timestamp": alert.get("timestamp"),
            "signature": alert.get("signature"),
            "severity": alert.get("severity"),
            "tactic": tactic,
            "technique_id": mitre.get("technique_id")
        })
        
    # Convert sets to lists for JSON serialization
    formatted_chains = []
    for ip, data in chains.items():
        data["tactics_observed"] = list(data["tactics_observed"])
        # Determine kill chain stage severity count
        formatted_chains.append(data)
        
    return formatted_chains
