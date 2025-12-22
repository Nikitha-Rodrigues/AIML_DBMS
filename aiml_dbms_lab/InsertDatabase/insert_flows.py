import json
import pymysql

# -----------------------
# 1. Read flows from flow_table.json
# -----------------------
with open("C:/Users/Nikitha/Downloads/5th_sem/aiml_dbms_lab/CapturePackets/flow_table.json", "r") as f:
    flows = json.load(f)

# Handle both single flow object and list of flows
if isinstance(flows, dict):
    flows = [flows]

if not flows:
    print("No flows found in flow_table.json")
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
    # 3. Insert each flow
    # -----------------------
    sql = """
    INSERT INTO flow (
        flow_id, source_ip, destination_ip, source_port, destination_port,
        protocol, flow_start_time, flow_end_time, flow_duration,
        total_fwd_packets, total_bwd_packets, total_length_fwd, total_length_bwd,
        fwd_packet_len_max, fwd_packet_len_min, fwd_packet_len_mean, fwd_packet_len_std,
        bwd_packet_len_max, bwd_packet_len_min, bwd_packet_len_mean, bwd_packet_len_std,
        flow_bytes_per_sec, flow_pkts_per_sec, fwd_pkts_per_sec, bwd_pkts_per_sec,
        flow_iat_max, flow_iat_min, flow_iat_mean, flow_iat_std,
        fwd_iat_total, fwd_iat_max, fwd_iat_min, fwd_iat_mean, fwd_iat_std,
        bwd_iat_total, bwd_iat_max, bwd_iat_min, bwd_iat_mean, bwd_iat_std,
        fwd_psh_flags, bwd_psh_flags, fwd_urg_flags, bwd_urg_flags,
        fin_flag_count, syn_flag_count, rst_flag_count, psh_flag_count,
        ack_flag_count, urg_flag_count, fwd_header_length, bwd_header_length,
        fwd_avg_bytes_per_bulk, fwd_avg_pkts_per_bulk, bwd_avg_bytes_per_bulk,
        bwd_avg_pkts_per_bulk, label
    )
    VALUES (
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s
    )
    ON DUPLICATE KEY UPDATE
        source_ip=VALUES(source_ip),
        destination_ip=VALUES(destination_ip),
        source_port=VALUES(source_port),
        destination_port=VALUES(destination_port),
        protocol=VALUES(protocol),
        flow_start_time=VALUES(flow_start_time),
        flow_end_time=VALUES(flow_end_time),
        flow_duration=VALUES(flow_duration),
        total_fwd_packets=VALUES(total_fwd_packets),
        total_bwd_packets=VALUES(total_bwd_packets),
        total_length_fwd=VALUES(total_length_fwd),
        total_length_bwd=VALUES(total_length_bwd),
        fwd_packet_len_max=VALUES(fwd_packet_len_max),
        fwd_packet_len_min=VALUES(fwd_packet_len_min),
        fwd_packet_len_mean=VALUES(fwd_packet_len_mean),
        fwd_packet_len_std=VALUES(fwd_packet_len_std),
        bwd_packet_len_max=VALUES(bwd_packet_len_max),
        bwd_packet_len_min=VALUES(bwd_packet_len_min),
        bwd_packet_len_mean=VALUES(bwd_packet_len_mean),
        bwd_packet_len_std=VALUES(bwd_packet_len_std),
        flow_bytes_per_sec=VALUES(flow_bytes_per_sec),
        flow_pkts_per_sec=VALUES(flow_pkts_per_sec),
        fwd_pkts_per_sec=VALUES(fwd_pkts_per_sec),
        bwd_pkts_per_sec=VALUES(bwd_pkts_per_sec),
        flow_iat_max=VALUES(flow_iat_max),
        flow_iat_min=VALUES(flow_iat_min),
        flow_iat_mean=VALUES(flow_iat_mean),
        flow_iat_std=VALUES(flow_iat_std),
        fwd_iat_total=VALUES(fwd_iat_total),
        fwd_iat_max=VALUES(fwd_iat_max),
        fwd_iat_min=VALUES(fwd_iat_min),
        fwd_iat_mean=VALUES(fwd_iat_mean),
        fwd_iat_std=VALUES(fwd_iat_std),
        bwd_iat_total=VALUES(bwd_iat_total),
        bwd_iat_max=VALUES(bwd_iat_max),
        bwd_iat_min=VALUES(bwd_iat_min),
        bwd_iat_mean=VALUES(bwd_iat_mean),
        bwd_iat_std=VALUES(bwd_iat_std),
        fwd_psh_flags=VALUES(fwd_psh_flags),
        bwd_psh_flags=VALUES(bwd_psh_flags),
        fwd_urg_flags=VALUES(fwd_urg_flags),
        bwd_urg_flags=VALUES(bwd_urg_flags),
        fin_flag_count=VALUES(fin_flag_count),
        syn_flag_count=VALUES(syn_flag_count),
        rst_flag_count=VALUES(rst_flag_count),
        psh_flag_count=VALUES(psh_flag_count),
        ack_flag_count=VALUES(ack_flag_count),
        urg_flag_count=VALUES(urg_flag_count),
        fwd_header_length=VALUES(fwd_header_length),
        bwd_header_length=VALUES(bwd_header_length),
        fwd_avg_bytes_per_bulk=VALUES(fwd_avg_bytes_per_bulk),
        fwd_avg_pkts_per_bulk=VALUES(fwd_avg_pkts_per_bulk),
        bwd_avg_bytes_per_bulk=VALUES(bwd_avg_bytes_per_bulk),
        bwd_avg_pkts_per_bulk=VALUES(bwd_avg_pkts_per_bulk),
        label=VALUES(label)
    """

    for flw in flows:
        values = (
            flw["FlowID"],
            flw["SourceIP"],
            flw["DestinationIP"],
            flw["SourcePort"],
            flw["DestinationPort"],
            flw["Protocol"],
            flw["FlowStartTime"],
            flw["FlowEndTime"],
            flw["FlowDuration"],
            flw["TotalFwdPackets"],
            flw["TotalBwdPackets"],
            flw["TotalLengthFwdPackets"],
            flw["TotalLengthBwdPackets"],
            flw["FwdPacketLengthMax"],
            flw["FwdPacketLengthMin"],
            flw["FwdPacketLengthMean"],
            flw["FwdPacketLengthStd"],
            flw["BwdPacketLengthMax"],
            flw["BwdPacketLengthMin"],
            flw["BwdPacketLengthMean"],
            flw["BwdPacketLengthStd"],
            flw["FlowBytesPerSec"],
            flw["FlowPktsPerSec"],
            flw["FwdPktsPerSec"],
            flw["BwdPktsPerSec"],
            flw["FlowIATMax"],
            flw["FlowIATMin"],
            flw["FlowIATMean"],
            flw["FlowIATStd"],
            flw["FwdIATTotal"],
            flw["FwdIATMax"],
            flw["FwdIATMin"],
            flw["FwdIATMean"],
            flw["FwdIATStd"],
            flw["BwdIATTotal"],
            flw["BwdIATMax"],
            flw["BwdIATMin"],
            flw["BwdIATMean"],
            flw["BwdIATStd"],
            flw["FwdPSHFlags"],
            flw["BwdPSHFlags"],
            flw["FwdURGFlags"],
            flw["BwdURGFlags"],
            flw["FINFlagCount"],
            flw["SYNFlagCount"],
            flw["RSTFlagCount"],
            flw["PSHFlagCount"],
            flw["ACKFlagCount"],
            flw["URGFlagCount"],
            flw["FwdHeaderLength"],
            flw["BwdHeaderLength"],
            flw["FwdAvgBytesPerBulk"],
            flw["FwdAvgPacketsPerBulk"],
            flw["BwdAvgBytesPerBulk"],
            flw["BwdAvgPacketsPerBulk"],
            flw["Label"]
        )

        cursor.execute(sql, values)

    db.commit()
    cursor.close()
    db.close()

    print(f"Inserted/updated {len(flows)} flows successfully!")