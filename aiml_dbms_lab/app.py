from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
import os
import pymysql
from pymongo import MongoClient
from functools import wraps

app = Flask(__name__, static_folder='static', static_url_path='/static')
# session secret for Flask; override via SECRET_KEY env var
app.secret_key = os.getenv('SECRET_KEY', 'change-me')
# allow cookies to be sent
CORS(app, supports_credentials=True)

# Configuration (environment variables optional)
MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
MYSQL_USER = os.getenv('MYSQL_USER', 'root')
MYSQL_PASS = os.getenv('MYSQL_PASS', '')
MYSQL_DB = os.getenv('MYSQL_DB', 'COVERT_CHANNEL')
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
MONGO_DB = os.getenv('MONGO_DB', 'covert_channel')

# MySQL helper
def get_mysql_conn():
    return pymysql.connect(host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASS, database=MYSQL_DB, cursorclass=pymysql.cursors.DictCursor)

# Mongo helper
mc = MongoClient(MONGO_URI)
mdb = mc[MONGO_DB]

# Static index
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

# Authentication helpers
def require_auth(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return wrapped

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or request.form
    username = (data.get('username') if data else None)
    password = (data.get('password') if data else None)
    valid_user = os.getenv('AUTH_USER', 'admin')
    valid_pass = os.getenv('AUTH_PASS', 'admin')
    if username == valid_user and password == valid_pass:
        session['authenticated'] = True
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('authenticated', None)
    return jsonify({'success': True})

@app.route('/api/auth-check')
def auth_check():
    return jsonify({'authenticated': bool(session.get('authenticated', False))})

# 1) System summary
@app.route('/api/summary')
def summary():
    sql_query = "SELECT (SELECT COUNT(*) FROM attack) AS total_attacks, (SELECT COUNT(*) FROM packet) AS total_packets, (SELECT COUNT(*) FROM flow) AS total_flows"
    try:
        conn = get_mysql_conn()
        with conn.cursor() as cur:
            cur.execute(sql_query)
            row = cur.fetchone()
        conn.close()
    except Exception as e:
        row = {'sql_error': str(e)}

    try:
        # Mongo side is simple counts, show descriptive text
        vuln_count = mdb.vulnerabilities.count_documents({})
        attacks_count = mdb.attacks.count_documents({})
        mongo = {'vulnerabilities': vuln_count, 'attacks': attacks_count, 'mongo_query': 'count documents in vulnerabilities and attacks collections'}
    except Exception as e:
        mongo = {'mongo_error': str(e)}

    return jsonify({'sql': {'query': sql_query, 'result': row}, 'mongo': mongo})

# 2) Latest attacks (SQL)
@app.route('/api/sql/latest-attacks')
def latest_attacks():
    limit = int(request.args.get('limit', 50))
    sql_query = "SELECT AttackID, AttackName, ModifiedField, ModifiedValue, OriginalValue, PacketID, FROM_UNIXTIME(Timestamp) AS ts FROM attack ORDER BY Timestamp DESC LIMIT %s"
    try:
        conn = get_mysql_conn()
        with conn.cursor() as cur:
            cur.execute(sql_query, (limit,))
            rows = cur.fetchall()
        conn.close()
        return jsonify({'query': sql_query.replace('%s', str(limit)), 'result': rows})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 3) Attack -> packet join (SQL)
@app.route('/api/sql/attack-details')
def attack_details():
    packet_id = request.args.get('packet_id')
    if not packet_id:
        return jsonify({'error': 'packet_id param required'}), 400
    sql_query = "SELECT a.AttackID, a.AttackName, a.ModifiedField, a.ModifiedValue, a.OriginalValue, p.* FROM attack a JOIN packet p ON a.PacketID = p.packet_id WHERE a.PacketID = %s LIMIT 1"
    try:
        conn = get_mysql_conn()
        with conn.cursor() as cur:
            cur.execute(sql_query, (packet_id,))
            row = cur.fetchone()
        conn.close()
        return jsonify({'query': sql_query.replace('%s', str(packet_id)), 'result': row or {}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 4) Attacks grouped by field
@app.route('/api/sql/attacks-by-field')
def attacks_by_field():
    # Optional: provide ?field=<field>&limit=<n> to get detailed rows for that field
    field = request.args.get('field')
    try:
        if field:
            allowed_fields = ['IPID', 'seq', 'ack', 'tcp_window', 'header_flags', 'src_ip', 'dst_ip']
            if field not in allowed_fields:
                return jsonify({'error': 'invalid field parameter', 'allowed': allowed_fields}), 400
            try:
                limit = int(request.args.get('limit', 500))
            except Exception:
                return jsonify({'error': 'invalid limit parameter'}), 400
            limit = max(1, min(limit, 1000))

            sql_query = ("SELECT a.AttackID, a.AttackName, a.ModifiedField, a.ModifiedValue, a.OriginalValue, a.PacketID, "
                         "p.packet_id, p.timestamp, p.src_ip, p.dst_ip, p.seq, p.IPID, p.ack, p.tcp_window "
                         "FROM attack a JOIN packet p ON a.PacketID = p.packet_id WHERE a.ModifiedField = %s "
                         "ORDER BY a.Timestamp DESC LIMIT %s")

            conn = get_mysql_conn()
            with conn.cursor() as cur:
                cur.execute(sql_query, (field, limit))
                rows = cur.fetchall()
            conn.close()

            # Build a simple human-friendly view for non-SQL users
            user_view = []
            for r in rows:
                pid = r.get('packet_id') or r.get('PacketID')
                ts = r.get('timestamp')
                src = r.get('src_ip') or ''
                dst = r.get('dst_ip') or ''
                mf = r.get('ModifiedField')
                ov = r.get('OriginalValue')
                mv = r.get('ModifiedValue')
                summary = f"Packet {pid} {src} -> {dst} at {ts}: {mf} changed {ov} → {mv}"
                user_view.append({'packet_id': pid, 'summary': summary})

            return jsonify({'query': sql_query, 'result': rows, 'user_view': user_view})

        # Default aggregated view
        sql_query = "SELECT ModifiedField, COUNT(*) AS cnt FROM attack GROUP BY ModifiedField ORDER BY cnt DESC"
        conn = get_mysql_conn()
        with conn.cursor() as cur:
            cur.execute(sql_query)
            rows = cur.fetchall()
        conn.close()
        return jsonify({'query': sql_query, 'result': rows})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 5) Flow summary
@app.route('/api/sql/flow-summary')
def flow_summary():
    # Inspect available columns for the `flow` table and build a safe SELECT
    try:
        conn = get_mysql_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME='flow'", (MYSQL_DB,))
            cols = {r['COLUMN_NAME'] for r in cur.fetchall()}
        conn.close()
    except Exception as e:
        return jsonify({'error': f'failed to inspect schema: {e}'}), 500

    # choose available column names and alias them to canonical names for frontend
    col_map = {}
    col_map['flow_id'] = 'flow_id' if 'flow_id' in cols else ('id' if 'id' in cols else None)
    col_map['src_ip'] = 'src_ip' if 'src_ip' in cols else ('source_ip' if 'source_ip' in cols else None)
    col_map['dst_ip'] = 'dst_ip' if 'dst_ip' in cols else ('destination_ip' if 'destination_ip' in cols else None)
    col_map['src_port'] = 'src_port' if 'src_port' in cols else ('source_port' if 'source_port' in cols else None)
    col_map['dst_port'] = 'dst_port' if 'dst_port' in cols else ('destination_port' if 'destination_port' in cols else None)
    col_map['packet_count'] = 'packet_count' if 'packet_count' in cols else ('total_fwd_packets' if 'total_fwd_packets' in cols else None)

    # Build select parts using available columns
    missing = [k for k,v in col_map.items() if v is None]
    # missing non-critical columns are okay; ensure at least flow_id exists
    if not col_map['flow_id']:
        return jsonify({'error': 'flow table missing flow_id column'}), 500

    select_parts = [f"{col_map['flow_id']} AS flow_id"]
    for key in ('src_ip','dst_ip','src_port','dst_port','packet_count'):
        if col_map.get(key):
            select_parts.append(f"{col_map[key]} AS {key}")

    sql_query = f"SELECT {', '.join(select_parts)} FROM flow ORDER BY { 'packet_count' if col_map.get('packet_count') else select_parts[1].split()[0] } DESC LIMIT 100"
    try:
        conn = get_mysql_conn()
        with conn.cursor() as cur:
            cur.execute(sql_query)
            rows = cur.fetchall()
        conn.close()
        return jsonify({'query': sql_query, 'result': rows})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 6) Packets in flow
@app.route('/api/sql/packets-in-flow')
def packets_in_flow():
    flow_id = request.args.get('flow_id')
    if not flow_id:
        return jsonify({'error': 'flow_id param required'}), 400
    if not str(flow_id).isdigit():
        return jsonify({'error': 'flow_id must be an integer'}), 400
    flow_id_int = int(flow_id)

    # Inspect packet table columns to pick available names
    try:
        conn = get_mysql_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME='packet'", (MYSQL_DB,))
            pkt_cols = {r['COLUMN_NAME'] for r in cur.fetchall()}
        conn.close()
    except Exception as e:
        return jsonify({'error': f'failed to inspect packet schema: {e}'}), 500

    # Determine which columns exist and alias them to canonical names
    col_map = {}
    col_map['packet_id'] = 'packet_id' if 'packet_id' in pkt_cols else ('id' if 'id' in pkt_cols else None)
    col_map['timestamp'] = 'timestamp' if 'timestamp' in pkt_cols else None
    col_map['src_ip'] = 'src_ip' if 'src_ip' in pkt_cols else ('source_ip' if 'source_ip' in pkt_cols else None)
    col_map['dst_ip'] = 'dst_ip' if 'dst_ip' in pkt_cols else ('destination_ip' if 'destination_ip' in pkt_cols else None)
    col_map['seq'] = 'seq' if 'seq' in pkt_cols else None
    col_map['IPID'] = 'IPID' if 'IPID' in pkt_cols else ('ipid' if 'ipid' in pkt_cols else None)
    col_map['ack'] = 'ack' if 'ack' in pkt_cols else None
    col_map['tcp_window'] = 'tcp_window' if 'tcp_window' in pkt_cols else ('window' if 'window' in pkt_cols else None)
    # flow id column in packet table
    flow_col = 'flow_id' if 'flow_id' in pkt_cols else ('flowid' if 'flowid' in pkt_cols else None)
    if not flow_col:
        return jsonify({'error': 'packet table missing flow_id column'}), 500

    select_parts = []
    for k in ['packet_id','timestamp','src_ip','dst_ip','seq','IPID','ack','tcp_window']:
        if col_map.get(k):
            select_parts.append(f"{col_map[k]} AS {k}")

    sql_query = f"SELECT {', '.join(select_parts)} FROM packet WHERE {flow_col}=%s ORDER BY { 'timestamp' if col_map.get('timestamp') else select_parts[0].split()[0] }"
    try:
        conn = get_mysql_conn()
        with conn.cursor() as cur:
            cur.execute(sql_query, (flow_id_int,))
            rows = cur.fetchall()
        conn.close()
        return jsonify({'query': sql_query.replace('%s', str(flow_id_int)), 'result': rows})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 7) IPID distribution
@app.route('/api/sql/ipid-distribution')
def ipid_distribution():
    flow_id = request.args.get('flow_id')
    if not flow_id:
        return jsonify({'error': 'flow_id param required'}), 400
    sql_query = "SELECT IPID AS value, COUNT(*) AS cnt FROM packet WHERE flow_id=%s GROUP BY IPID ORDER BY cnt DESC LIMIT 200"
    try:
        conn = get_mysql_conn()
        with conn.cursor() as cur:
            cur.execute(sql_query, (flow_id,))
            rows = cur.fetchall()
        conn.close()
        return jsonify({'query': sql_query.replace('%s', str(flow_id)), 'result': rows})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 8) Mongo: vulnerabilities list
@app.route('/api/mongo/vulnerabilities')
def mongo_vulns():
    mongo_query = "db.vulnerabilities.find({}, {created_at:0, modified_at:0})"
    try:
        docs = list(mdb.vulnerabilities.find({}, {'created_at':0, 'modified_at':0}))
        # Convert ObjectId to str for JSON
        for d in docs:
            d['_id'] = str(d.get('_id'))
        return jsonify({'query': mongo_query, 'result': docs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 9) Mongo: attacks with vulnerability (joined)
@app.route('/api/mongo/attacks-with-vuln')
def mongo_attacks_with_vuln():
    limit = int(request.args.get('limit', 100))
    pipeline = [
        { '$lookup': { 'from': 'vulnerabilities', 'localField': 'vulnerability_id', 'foreignField': '_id', 'as': 'vuln' } },
        { '$unwind': { 'path': '$vuln', 'preserveNullAndEmptyArrays': True } },
        { '$project': { 'attack_name':1, 'modified_field':1, 'modified_value':1, 'original_value':1, 'packet_id':1, 'timestamp':1, 'vuln.name':1, 'vuln.severity':1 } },
        { '$sort': { 'timestamp': -1 } },
        { '$limit': limit }
    ]
    try:
        docs = list(mdb.attacks.aggregate(pipeline))
        for d in docs:
            d['_id'] = str(d.get('_id'))
            if 'vuln' in d:
                d['vuln']['_id'] = str(d['vuln'].get('_id'))
        return jsonify({'query': pipeline, 'result': docs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5003))
    app.run(host='0.0.0.0', port=port, debug=True)
