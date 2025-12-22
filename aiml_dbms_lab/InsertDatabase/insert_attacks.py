from asyncio.windows_events import NULL
import json
import pymysql  # or sqlite3 depending on your DB

# -----------------------
# 1. Read attack_log.json and captured.json
# -----------------------
with open("C:/Users/Nikitha/Downloads/5th_sem/aiml_dbms_lab/SendPackets/attack_log.json", "r") as f:
    attacks = json.load(f)

with open("C:/Users/Nikitha/Downloads/5th_sem/aiml_dbms_lab/CapturePackets/captured.json", "r") as f:
    packets = json.load(f)

# Create a mapping from seq value to packet_id (from captured.json)
seq_to_packet_id = {pkt["seq"]: pkt["packet_id"] for pkt in packets}

# Filter attacks: only keep those where modified_value matches a captured packet's seq

# Keep only attacks whose modified_value maps to a captured packet seq
matching_attacks = []
for atk in attacks:
    if atk["modified_value"] in seq_to_packet_id:
        # Add the actual packet_id from captured.json
        atk["packet_id_from_captured"] = seq_to_packet_id[atk["modified_value"]]
        matching_attacks.append(atk)

print(f"Total attacks in attack_log.json: {len(attacks)}")
print(f"Matching attacks (modified_value in captured.json seq): {len(matching_attacks)}")

# Deduplicate attacks so there's at most one attack per matched packet.
# This keeps the first attack encountered for each `packet_id_from_captured`.
unique_by_packet = {}
for atk in matching_attacks:
    pid = atk["packet_id_from_captured"]
    if pid not in unique_by_packet:
        unique_by_packet[pid] = atk

unique_attacks = list(unique_by_packet.values())
duplicates = len(matching_attacks) - len(unique_attacks)
if duplicates > 0:
    print(f"Removed {duplicates} duplicate attack(s) mapping to the same packet_id; keeping first occurrence per packet.")

print(f"Attacks to insert after deduplication: {len(unique_attacks)}")

if not matching_attacks:
    print("No matching attacks found. Exiting.")
else:
    # -----------------------
    # 2. Connect to database
    # -----------------------
    db = pymysql.connect(
        host="localhost",
        user="root",
        password="Qplb@1716122",
        database="COVERT_CHANNEL"
    )

    cursor = db.cursor()

    # -----------------------
    # 3. Insert each matching attack
    # -----------------------
    sql = """
    INSERT INTO attack (
        AttackID, PacketID, AttackName, ModifiedField, ModifiedValue, OriginalValue, Timestamp
    )
    VALUES (%s, %s, %s, %s, %s,
            %s, %s)
    ON DUPLICATE KEY UPDATE
        AttackID=VALUES(AttackID),
        PacketID=VALUES(PacketID),
        AttackName=VALUES(AttackName),
        ModifiedField=VALUES(ModifiedField),
        ModifiedValue=VALUES(ModifiedValue),
        OriginalValue=VALUES(OriginalValue),
        Timestamp=VALUES(Timestamp)
    """

    for i, atk in enumerate(unique_attacks, start=1):
        # Use the packet_id from captured.json (which should match the database after insert_packets.py)
        packet_id_to_use = atk["packet_id_from_captured"]
        
        values = (
            i,  # AttackID - auto-incrementing, separate from PacketID
            packet_id_to_use,  # PacketID - use the matched packet_id from captured.json
            None,  # AttackName
            atk["modified_field"],
            atk["modified_value"],
            atk["original_value"],
            atk["timestamp"]
        )

        cursor.execute(sql, values)

    db.commit()
    cursor.close()
    db.close()

    print(f"Inserted/updated {len(matching_attacks)} matching attacks successfully!")