from scapy.all import IP, TCP, send
import time
import json
import random
from datetime import datetime

ATTACK_LOG_PATH = "C:/Users/Nikitha/Downloads/5th_sem/aiml_dbms_lab/SendPackets/attack_log.json"
SAMPLE_TEXT = "C:/Users/Nikitha/Downloads/5th_sem/aiml_dbms_lab/sample_text.txt"

# -------------------------
# Convert 4 characters -> 32-bit ACK value
# -------------------------
def chars_to_ack(chars):
    chars = chars.ljust(4)[:4]
    b = chars.encode('utf-8', errors='replace')
    return int.from_bytes(b, 'big')


# -------------------------
# Load file -> return list of (block, ack_num)
# -------------------------
def load_chunks(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()

    # pad text to multiple of 4
    while len(text) % 4 != 0:
        text += " "

    chunks = []
    for i in range(0, len(text), 4):
        block = text[i:i+4]
        num = chars_to_ack(block)
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
# Send packets carrying covert data inside ACK field
# -------------------------
def send_ack_chunks(chunks, src_ip, dst_ip, dport=80, inter=0.02):
    packets = []
    seq_base = 1000  # baseline sequence number (left mostly unchanged)
    
    # Start with a random 32-bit ACK value and increment
    initial_ack = random.randint(0, 2**32 - 1)
    current_ack = initial_ack

    # determine next attack log id
    try:
        with open(ATTACK_LOG_PATH, 'r', encoding='utf-8') as f:
            existing = json.load(f)
            next_attack_id = (max((e.get('packet_id', 0) for e in existing), default=0) + 1) if existing else 1
    except (FileNotFoundError, json.JSONDecodeError):
        next_attack_id = 1

    for index, (block, ack_num) in enumerate(chunks):
        pkt = IP(src=src_ip, dst=dst_ip, id=index) / TCP(
            sport=44444,
            dport=dport,
            seq=seq_base + index,  # keep seq as baseline
            ack=ack_num,  # covert data in ACK field
            flags="A"
        )

        packets.append(pkt)
        send(pkt, verbose=False)
        print(f"Sent block '{block}' as ACK={ack_num} (original_ack={current_ack})")

        # Log the attack in the attack_log.json array
        bits = ''.join(f'{ord(c):08b}' for c in block)
        entry = {
            "packet_id": next_attack_id,
            "modified_field": "Ack",
            "original_value": current_ack,  # incrementing 32-bit original ACK
            "modified_value": ack_num,
            "covert_bits": bits,
            "timestamp": datetime.now().timestamp()
        }

        append_attack_log(entry)
        next_attack_id += 1
        
        # Increment original ACK value for next packet
        current_ack = (current_ack + 1) & 0xFFFFFFFF  # wrap around at 2^32

        time.sleep(inter)

    return packets


if __name__ == "__main__":
    file_path = SAMPLE_TEXT
    src_ip = "198.168.1.6"
    dst_ip = "198.168.1.6"
    dport = 9966

    chunks = load_chunks(file_path)
    print(f"Loaded {len(chunks)} blocks.")

    send_ack_chunks(chunks, src_ip, dst_ip, dport)
