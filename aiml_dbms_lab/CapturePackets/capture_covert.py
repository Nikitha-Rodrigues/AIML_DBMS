from scapy.all import sniff, IP, TCP,Ether
import time
import json

captured_packets = []

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
    # pkt is a Scapy packet object, access layers properly
    a = (pkt[IP].src, pkt[TCP].sport)
    b = (pkt[IP].dst, pkt[TCP].dport)

    # Sort endpoints so order doesn't matter
    ep1, ep2 = sorted([a, b])

    return f"{ep1[0]}:{ep1[1]}-{ep2[0]}:{ep2[1]}"

def extract_packet_entry(pkt, flow_id):
    global next_packet_id
    # Basic header lengths
    eth_len = 14 if Ether in pkt else 0
    ip_len = pkt[IP].ihl * 4 if IP in pkt else 0
    tcp_len = pkt[TCP].dataofs * 4 if TCP in pkt else 0
    tcp_payload_len = len(pkt[TCP].payload) if TCP in pkt else 0

    entry = {
        "packet_id": next_packet_id,
        "flow_id": canonical_flow_id(pkt),
        "timestamp": time.time(),

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
        "IAT": compute_IAT(flow_id, time.time()),


        # Label (normal or covert)
        "Label": "covert" if is_covert_packet(pkt) else "normal"
    }

    # increment global counter for next packet
    next_packet_id += 1

    return entry

def compute_IAT(flow_id, current_time):
    if flow_id not in last_packet_time:
        last_packet_time[flow_id] = current_time
        return 0.0

    iat = current_time - last_packet_time[flow_id]
    last_packet_time[flow_id] = current_time
    return iat

def is_covert_packet(pkt):
    # Example check: TCP sequence used to encode text (ASCII range)
    seq = pkt[TCP].seq

    # Heuristic: covert sequence numbers are between ASCII ranges
    return 32 <= (seq & 0xFF) <= 126

def pkt_callback(pkt):
    flow_id = f"{pkt[IP].src}-{pkt[IP].dst}-{pkt[TCP].sport}-{pkt[TCP].dport}"
    entry = extract_packet_entry(pkt, flow_id)
    if entry["Label"] == "covert":
        packet_table.append(entry)

        #write to captured.json
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
        print(f"[COVERT] packet_id={entry['packet_id']} seq={entry['seq']}")


print("Listening for outgoing packets containing covert data...")
sniff(filter="tcp and src host 198.168.1.6", prn=pkt_callback, store=False, timeout=10)

print("Saved to captured.json")
