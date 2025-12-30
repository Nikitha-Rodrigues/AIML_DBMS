"""
Migrate attacks from MySQL `attack` table into MongoDB `attacks` collection and link to vulnerability documents.
Run after seeding vulnerabilities.
"""
import pymysql
from pymongo import MongoClient

# MySQL connection
mysql_db = pymysql.connect(host="localhost", user="root", password="", database="COVERT_CHANNEL")
cur = mysql_db.cursor(pymysql.cursors.DictCursor)
cur.execute("SELECT * FROM attack")
rows = cur.fetchall()

# Mongo connection
mc = MongoClient("mongodb://localhost:27017")
mdb = mc.covert_channel
vulns = mdb.vulnerabilities
attacks_col = mdb.attacks

# Build map: affected_field (lower) -> vuln_id
vmap = {}
for v in vulns.find():
    for f in v.get("affected_fields", []):
        vmap[f.lower()] = v["_id"]

inserted = 0
for r in rows:
    mf = (r.get("ModifiedField") or "").lower()
    vuln_id = vmap.get(mf)
    doc = {
        "attack_name": r.get("AttackName"),
        "modified_field": r.get("ModifiedField"),
        "modified_value": r.get("ModifiedValue"),
        "original_value": r.get("OriginalValue"),
        "packet_id": r.get("PacketID"),
        "timestamp": r.get("Timestamp"),
        "vulnerability_id": vuln_id
    }
    attacks_col.update_one({"attack_name": doc["attack_name"], "packet_id": doc["packet_id"]}, {"$set": doc}, upsert=True)
    inserted += 1

print(f"Upserted {inserted} attacks into MongoDB.")

cur.close()
mysql_db.close()
mc.close()
