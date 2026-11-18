import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel-mitigation")

def block_ip_address(ip_address: str):
    """
    Simulates or executes a firewall block for a malicious IP address.
    In production on Linux, this can interact with nftables or iptables.
    """
    logger.warning(f"[!] SECURITY ACTION: Blocking malicious IP: {ip_address}")
    
    # Example simulated rule insertion (safe for development / container node)
    # try:
    #     subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
    # except Exception as e:
    #     logger.error(f"Failed to apply iptables rule: {e}")
    
    return {
        "status": "success",
        "action": "BLOCK_IP",
        "target": ip_address,
        "message": f"Successfully isolated and blocked traffic from {ip_address}"
    }
