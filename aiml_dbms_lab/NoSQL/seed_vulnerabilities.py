"""
Seed script for MongoDB vulnerabilities collection used by the AIML_DBMS project.
Creates/updates vulnerability documents relevant to covert channels tested in this repo.

Usage:
  - Ensure MongoDB is running locally (mongodb://localhost:27017)
  - Activate your virtualenv and install pymongo: pip install pymongo
  - Run: python3 aiml_dbms_lab/NoSQL/seed_vulnerabilities.py
"""
from pymongo import MongoClient
from datetime import datetime

client = MongoClient("mongodb://localhost:27017")
# Database name chosen to be lower-case 'covert_channel'
db = client.covert_channel
vulns = db.vulnerabilities

now = datetime.utcnow()

docs = [
    {
        "name": "IPID Covert Channel",
        "cwe_category": "CWE-200",  # Information Exposure
        "description": "Use of the IPv4 Identification (IPID) field to encode covert data across packets allowing data exfiltration.",
        "severity": "High",
        "severity_score": 7.5,
        "affected_fields": ["IPID", "IpId"],
        "impact": "Covert exfiltration of data; difficult to detect without monitoring field distributions.",
        "mitigations": [
            "Randomize IPID allocation in the OS network stack",
            "Block or normalize suspicious IPID patterns at network perimeter",
            "Network monitoring and anomaly detection for IPID entropy/sequence"
        ],
        "references": [
            "https://en.wikipedia.org/wiki/IPv4#Identification",
        ],
        "created_at": now,
        "modified_at": now
    },
    {
        "name": "TCP Sequence Number Covert Channel",
        "cwe_category": "CWE-200",
        "description": "Embedding covert data inside TCP sequence numbers. Attackers set chosen sequence values to carry payload bits.",
        "severity": "High",
        "severity_score": 7.0,
        "affected_fields": ["seq", "sequence", "SEQ"],
        "impact": "Covert channels in TCP header enabling data leakage and stealthy signalling.",
        "mitigations": [
            "Normalize sequence numbers where possible",
            "Deep packet inspection for out-of-band sequence value anomalies",
        ],
        "references": [],
        "created_at": now,
        "modified_at": now
    },
    {
        "name": "TCP Window Size Covert Channel",
        "cwe_category": "CWE-200",
        "description": "Using the TCP window-size field to encode information (changes to window value as covert bits).",
        "severity": "Medium",
        "severity_score": 6.0,
        "affected_fields": ["window", "tcp_window", "Window"],
        "impact": "May leak small amounts of data or be used as a signalling channel.",
        "mitigations": [
            "Monitor window-size distributions and outliers",
            "Use middleboxes to normalize TCP window values if appropriate"
        ],
        "references": [],
        "created_at": now,
        "modified_at": now
    },
    {
        "name": "TCP ACK Covert Channel",
        "cwe_category": "CWE-200",
        "description": "Embedding covert data in TCP ACK numbers or ACK-related timing behaviour.",
        "severity": "Medium",
        "severity_score": 6.0,
        "affected_fields": ["ack", "ACK"],
        "impact": "Covert signaling/low-bandwidth exfiltration via ACK manipulation.",
        "mitigations": [
            "Detect abnormal ACK number patterns",
            "Limit acceptance of out-of-window ACK values"
        ],
        "references": [],
        "created_at": now,
        "modified_at": now
    },
    {
        "name": "Protocol Field Manipulation (general)",
        "cwe_category": "CWE-200",
        "description": "Manipulation of protocol header fields (IP/TCP) to carry covert information. General category used for classification.",
        "severity": "Medium",
        "severity_score": 6.5,
        "affected_fields": ["IPID","seq","ack","window"],
        "impact": "Various covert channels possible; detection requires correlation across multiple fields/flows.",
        "mitigations": ["Field normalization, anomaly detection, network segmentation"],
        "references": [],
        "created_at": now,
        "modified_at": now
    },
    {
        "name": "Timing Covert Channel",
        "cwe_category": "CWE-209",
        "description": "Encoding data in packet timing (inter-packet delays) to form a covert channel.",
        "severity": "Medium",
        "severity_score": 6.0,
        "affected_fields": ["timing","inter-arrival-times"],
        "impact": "Stealthy low-bandwidth channels that can bypass simple header-field inspection.",
        "mitigations": ["Traffic shaping, jittering, anomaly detection on timing"],
        "references": [],
        "created_at": now,
        "modified_at": now
    }
]

# Upsert each vulnerability by name so the seed is idempotent
for d in docs:
    vulns.update_one({"name": d["name"]}, {"$set": d}, upsert=True)

print("Seeded/updated vulnerabilities in MongoDB (db: covert_channel, collection: vulnerabilities).")
client.close()
