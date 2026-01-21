from __future__ import annotations
import subprocess

def ipset_create(set_name: str, timeout: int) -> None:
    subprocess.run(["ipset", "create", set_name, "hash:ip", "timeout", str(timeout), "-exist"], check=False)

def ipset_add(set_name: str, ip: str, timeout: int) -> None:
    subprocess.run(["ipset", "add", set_name, ip, "timeout", str(timeout), "-exist"], check=False)

def nft_apply_forward_drop(set_name: str, table: str = "inet", chain: str = "forward") -> None:
    subprocess.run(["nft", "add", "table", table, "filter"], check=False)
    subprocess.run([
        "nft", "add", "chain", table, "filter", chain,
        "{", "type", "filter", "hook", chain, "priority", "0", ";", "policy", "accept", ";", "}"
    ], check=False)

    out = subprocess.run(["nft", "list", "chain", table, "filter", chain], capture_output=True, text=True, check=False).stdout
    if set_name not in out:
        subprocess.run([
            "nft", "add", "rule", table, "filter", chain,
            "ip", "saddr", f"@{set_name}", "drop",
            "comment", "MiniFW-AI blocklist"
        ], check=False)
