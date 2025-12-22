from scapy.all import sniff, IP, TCP, Ether
import time
import json

# Local state
packet_table = []
last_packet_time = {}

# Determine next packet_id based on existing captured.json (if any)
next_packet_id = 1
try:
    with open("captured.json", "r") as f:
        content = f.read().strip()
        if content:
            existing = json.loads(content)
            if isinstance(existing, list) and len(existing) > 0:
                max_id = max(p.get("packet_id", 0) for p in existing)
                next_packet_id = max_id + 1
except (FileNotFoundError, json.JSONDecodeError):
    next_packet_id = 1


def canonical_flow_id(pkt):
    """Return a flow id that is direction-agnostic: ip:port-ip:port with endpoints sorted."""
    a = (pkt[IP].src, pkt[TCP].sport)
    b = (pkt[IP].dst, pkt[TCP].dport)
    ep1, ep2 = sorted([a, b])
    return f"{ep1[0]}:{ep1[1]}-{ep2[0]}:{ep2[1]}"


def compute_IAT(flow_id, current_time):
    if flow_id not in last_packet_time:
        last_packet_time[flow_id] = current_time
        return 0.0
    iat = current_time - last_packet_time[flow_id]
    last_packet_time[flow_id] = current_time
    return iat


def is_ipid_covert(pkt):
    """Return True if both bytes of IP ID are printable ASCII characters (32..126)."""
    try:
        ipid = pkt[IP].id
    except Exception:
        return False
    hi = (ipid >> 8) & 0xFF
    lo = ipid & 0xFF
    return (32 <= hi <= 126) and (32 <= lo <= 126)


def extract_packet_entry(pkt):
    """Build the packet dictionary matching the format used by other scripts."""
    global next_packet_id

    eth_len = 14 if Ether in pkt else 0
    ip_len = pkt[IP].ihl * 4 if IP in pkt else 0
    tcp_len = pkt[TCP].dataofs * 4 if TCP in pkt else 0
    tcp_payload_len = len(pkt[TCP].payload) if TCP in pkt else 0

    flow_id = canonical_flow_id(pkt)
    ts = time.time()

    entry = {
        "packet_id": next_packet_id,
        "flow_id": flow_id,
        "timestamp": ts,

        # IP / Transport metadata
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "src_port": pkt[TCP].sport,
        "dst_port": pkt[TCP].dport,
        "protocol": "TCP",

        # Lengths
        "packet_length": len(pkt),
        "ip_total_length": pkt[IP].len,
        "ip_header_length": ip_len,
        "ethernet_header_length": eth_len,
        "tcp_header_length": tcp_len,
        "tcp_payload_length": tcp_payload_len,

        # TCP fields
        "seq": pkt[TCP].seq,
        "ack": pkt[TCP].ack,
        "tcp_fin": int(pkt[TCP].flags.F),
        "tcp_syn": int(pkt[TCP].flags.S),
        "tcp_rst": int(pkt[TCP].flags.R),
        "tcp_psh": int(pkt[TCP].flags.P),
        "tcp_ack": int(pkt[TCP].flags.A),
        "tcp_urg": int(pkt[TCP].flags.U),

        # IP fields
        "ip_flags": pkt[IP].flags.value,
        "ip_ttl": pkt[IP].ttl,
        "tcp_window": pkt[TCP].window,
        "tcp_dataofs": pkt[TCP].dataofs,
        "tcp_reserved": pkt[TCP].reserved,

        # IPID
        "IPID": pkt[IP].id,

        # Inter-arrival time (IAT)
        "IAT": compute_IAT(flow_id, ts),

        # Label (normal or covert)
        "Label": "covert" if is_ipid_covert(pkt) else "normal"
    }

    # increment global counter for next packet
    next_packet_id += 1

    return entry


def pkt_callback(pkt):
    # only consider IP/TCP packets
    if IP not in pkt or TCP not in pkt:
        return

    # check IPID covert condition
    if not is_ipid_covert(pkt):
        return

    entry = extract_packet_entry(pkt)

    # append to captured.json
    try:
        with open("captured.json", "r") as f:
            content = f.read().strip()
            if content:
                data = json.loads(content)
            else:
                data = []
    except (FileNotFoundError, json.JSONDecodeError):
        data = []

    data.append(entry)
    with open("captured.json", "w") as f:
        json.dump(data, f, indent=4)

    print(f"[IPID COVERT] packet_id={entry['packet_id']} IPID={entry['IPID']}")


if __name__ == "__main__":
    print("Listening for outgoing IPID-based covert packets...")
    sniff(filter="tcp and src host 198.168.1.6", prn=pkt_callback, store=False, timeout=10)
    print("Saved to captured.json")
