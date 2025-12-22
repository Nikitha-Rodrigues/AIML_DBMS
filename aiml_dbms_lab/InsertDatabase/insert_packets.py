import json
import pymysql  # or sqlite3 depending on your DB

# -----------------------
# 1. Read packets from captured.json
# -----------------------
with open("C:/Users/Nikitha/Downloads/5th_sem/aiml_dbms_lab/CapturePackets/captured.json", "r") as f:
    packets = json.load(f)

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
# 3. Insert each packet
# -----------------------
sql = """
INSERT INTO packet (
    packet_id, flow_id, timestamp, src_ip, dst_ip,
    src_port, dst_port, protocol, packet_length,
    ip_total_length, ip_header_length, ethernet_header_length,
    tcp_header_length, tcp_payload_length, seq, ack,
    tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, tcp_urg,
    ip_flags, ip_ttl, tcp_window, tcp_dataofs, tcp_reserved,
    IPID, IAT, Label
)
VALUES (%s, %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s, %s)
ON DUPLICATE KEY UPDATE
    flow_id=VALUES(flow_id),
    timestamp=VALUES(timestamp),
    src_ip=VALUES(src_ip),
    dst_ip=VALUES(dst_ip),
    src_port=VALUES(src_port),
    dst_port=VALUES(dst_port),
    protocol=VALUES(protocol),
    packet_length=VALUES(packet_length),
    ip_total_length=VALUES(ip_total_length),
    ip_header_length=VALUES(ip_header_length),
    ethernet_header_length=VALUES(ethernet_header_length),
    tcp_header_length=VALUES(tcp_header_length),
    tcp_payload_length=VALUES(tcp_payload_length),
    seq=VALUES(seq),
    ack=VALUES(ack),
    tcp_fin=VALUES(tcp_fin),
    tcp_syn=VALUES(tcp_syn),
    tcp_rst=VALUES(tcp_rst),
    tcp_psh=VALUES(tcp_psh),
    tcp_ack=VALUES(tcp_ack),
    tcp_urg=VALUES(tcp_urg),
    ip_flags=VALUES(ip_flags),
    ip_ttl=VALUES(ip_ttl),
    tcp_window=VALUES(tcp_window),
    tcp_dataofs=VALUES(tcp_dataofs),
    tcp_reserved=VALUES(tcp_reserved),
    IPID=VALUES(IPID),
    IAT=VALUES(IAT),
    Label=VALUES(Label)
"""

for pkt in packets:
    values = (
        pkt["packet_id"],
        pkt["flow_id"],
        pkt["timestamp"],
        pkt["src_ip"],
        pkt["dst_ip"],
        pkt["src_port"],
        pkt["dst_port"],
        pkt["protocol"],
        pkt["packet_length"],
        pkt["ip_total_length"],
        pkt["ip_header_length"],
        pkt["ethernet_header_length"],
        pkt["tcp_header_length"],
        pkt["tcp_payload_length"],
        pkt["seq"],
        pkt["ack"],
        pkt["tcp_fin"],
        pkt["tcp_syn"],
        pkt["tcp_rst"],
        pkt["tcp_psh"],
        pkt["tcp_ack"],
        pkt["tcp_urg"],
        pkt["ip_flags"],
        pkt["ip_ttl"],
        pkt["tcp_window"],
        pkt["tcp_dataofs"],
        pkt["tcp_reserved"],
        pkt["IPID"],
        pkt["IAT"],
        pkt["Label"]
    )

    cursor.execute(sql, values)

db.commit()
cursor.close()
db.close()

print("Packets inserted successfully!")