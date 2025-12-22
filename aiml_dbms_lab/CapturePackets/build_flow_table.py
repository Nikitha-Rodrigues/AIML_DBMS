import json
from statistics import mean, stdev

def build_flows(file_path="captured.json"):
    """Build flow entries from captured packets, grouped by flow_id"""
    with open(file_path, "r") as f:
        packets = json.load(f)

    if len(packets) == 0:
        print("No packets found.")
        return []

    # -----------------------
    # Group packets by flow_id
    # -----------------------
    flows_dict = {}
    for pkt in packets:
        flow_id = pkt["flow_id"]
        if flow_id not in flows_dict:
            flows_dict[flow_id] = []
        flows_dict[flow_id].append(pkt)

    # -----------------------
    # Determine starting FlowID based on existing flow_table.json
    # -----------------------
    flow_entries = []
    flow_counter = 1

    for flow_id, packets_in_flow in flows_dict.items():
        flow_entry = build_single_flow(flow_id, packets_in_flow, flow_counter)
        flow_entries.append(flow_entry)
        flow_counter += 1

    return flow_entries


def build_single_flow(flow_id, packets, flow_counter):
    """Build a single flow entry from packets belonging to that flow"""
    # -----------------------
    # Identify forward/backward direction
    # -----------------------
    srcA = packets[0]["src_ip"]
    dstA = packets[0]["dst_ip"]

    forward = []
    backward = []

    for pkt in packets:
        if pkt["src_ip"] == srcA and pkt["dst_ip"] == dstA:
            forward.append(pkt)
        else:
            backward.append(pkt)

    # -----------------------
    # Basic timing
    # -----------------------
    timestamps = [p["timestamp"] for p in packets]
    start = min(timestamps)
    end = max(timestamps)
    duration = end - start if end > start else 0.000001

    # -----------------------
    # Flow metrics
    # -----------------------
    total_fwd = len(forward)
    total_bwd = len(backward)

    # Packet lengths
    fwd_lengths = [p["packet_length"] for p in forward]
    bwd_lengths = [p["packet_length"] for p in backward]

    def safe_mean(x): return mean(x) if len(x) else 0
    def safe_std(x): return stdev(x) if len(x) > 1 else 0
    def safe_min(x): return min(x) if len(x) else 0
    def safe_max(x): return max(x) if len(x) else 0
    def safe_sum(x): return sum(x) if len(x) else 0

    # Inter-arrival times
    def iat_list(pkts):
        times = [p["timestamp"] for p in pkts]
        if len(times) < 2:
            return []
        return [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]

    fwd_iat = iat_list(forward)
    bwd_iat = iat_list(backward)
    flow_iat = iat_list(packets)

    # -----------------------
    # FLAG COUNT using new fields
    # -----------------------
    def count_field(pkts, name):
        return sum(p[name] for p in pkts)

    FIN = count_field(packets, "tcp_fin")
    SYN = count_field(packets, "tcp_syn")
    RST = count_field(packets, "tcp_rst")
    PSH = count_field(packets, "tcp_psh")
    ACK = count_field(packets, "tcp_ack")
    URG = count_field(packets, "tcp_urg")

    fwd_psh = count_field(forward, "tcp_psh")
    bwd_psh = count_field(backward, "tcp_psh")
    fwd_urg = count_field(forward, "tcp_urg")
    bwd_urg = count_field(backward, "tcp_urg")

    # -----------------------
    # Header lengths
    # -----------------------
    fwd_header_len = safe_sum([p["ip_header_length"] + p["tcp_header_length"] for p in forward])
    bwd_header_len = safe_sum([p["ip_header_length"] + p["tcp_header_length"] for p in backward])

    # -----------------------
    # Rates
    # -----------------------
    flow_bytes_per_sec = safe_sum(fwd_lengths + bwd_lengths) / duration
    flow_pkts_per_sec = len(packets) / duration
    fwd_pkts_per_sec = total_fwd / duration
    bwd_pkts_per_sec = total_bwd / duration

    # -----------------------
    # Bulk metrics
    # -----------------------
    fwd_bulk_bytes = safe_sum(fwd_lengths)
    bwd_bulk_bytes = safe_sum(bwd_lengths)

    flow_entry = {
        "FlowID": flow_counter,
        "SourceIP": srcA,
        "DestinationIP": dstA,
        "SourcePort": packets[0]["src_port"],
        "DestinationPort": packets[0]["dst_port"],
        "Protocol": "TCP",
        "FlowStartTime": start,
        "FlowEndTime": end,
        "FlowDuration": duration,

        "TotalFwdPackets": total_fwd,
        "TotalBwdPackets": total_bwd,

        "TotalLengthFwdPackets": safe_sum(fwd_lengths),
        "TotalLengthBwdPackets": safe_sum(bwd_lengths),

        "FwdPacketLengthMax": safe_max(fwd_lengths),
        "FwdPacketLengthMin": safe_min(fwd_lengths),
        "FwdPacketLengthMean": safe_mean(fwd_lengths),
        "FwdPacketLengthStd": safe_std(fwd_lengths),

        "BwdPacketLengthMax": safe_max(bwd_lengths),
        "BwdPacketLengthMin": safe_min(bwd_lengths),
        "BwdPacketLengthMean": safe_mean(bwd_lengths),
        "BwdPacketLengthStd": safe_std(bwd_lengths),

        "FlowBytesPerSec": flow_bytes_per_sec,
        "FlowPktsPerSec": flow_pkts_per_sec,
        "FwdPktsPerSec": fwd_pkts_per_sec,
        "BwdPktsPerSec": bwd_pkts_per_sec,

        "FlowIATMax": safe_max(flow_iat),
        "FlowIATMin": safe_min(flow_iat),
        "FlowIATMean": safe_mean(flow_iat),
        "FlowIATStd": safe_std(flow_iat),

        "FwdIATTotal": safe_sum(fwd_iat),
        "FwdIATMax": safe_max(fwd_iat),
        "FwdIATMin": safe_min(fwd_iat),
        "FwdIATMean": safe_mean(fwd_iat),
        "FwdIATStd": safe_std(fwd_iat),

        "BwdIATTotal": safe_sum(bwd_iat),
        "BwdIATMax": safe_max(bwd_iat),
        "BwdIATMin": safe_min(bwd_iat),
        "BwdIATMean": safe_mean(bwd_iat),
        "BwdIATStd": safe_std(bwd_iat),

        "FwdPSHFlags": fwd_psh,
        "BwdPSHFlags": bwd_psh,

        "FwdURGFlags": fwd_urg,
        "BwdURGFlags": bwd_urg,

        "FINFlagCount": FIN,
        "SYNFlagCount": SYN,
        "RSTFlagCount": RST,
        "PSHFlagCount": PSH,
        "ACKFlagCount": ACK,
        "URGFlagCount": URG,

        "FwdHeaderLength": fwd_header_len,
        "BwdHeaderLength": bwd_header_len,

        "FwdAvgBytesPerBulk": fwd_bulk_bytes,
        "FwdAvgPacketsPerBulk": total_fwd,
        "BwdAvgBytesPerBulk": bwd_bulk_bytes,
        "BwdAvgPacketsPerBulk": total_bwd,

        "Label": "Covert-Channel"
    }

    return flow_entry


if __name__ == "__main__":
    flows = build_flows()
    print(f"Built {len(flows)} flow entries")
    # Debug: show flow summary
    for i, flow in enumerate(flows, 1):
        print(f"  Flow {i}: {flow['SourceIP']} → {flow['DestinationIP']} "
              f"({flow['SourcePort']}:{flow['DestinationPort']}) | "
              f"Fwd: {flow['TotalFwdPackets']} pkts, Bwd: {flow['TotalBwdPackets']} pkts")

    # Write flows to file (overwrite, don't append)
    with open("flow_table.json", "w") as f:
        json.dump(flows, f, indent=4)

    print(f"Saved {len(flows)} flows to flow_table.json")
