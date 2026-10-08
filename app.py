from flask import Flask, render_template, request, redirect, session
import sqlite3


app = Flask(__name__)

app.secret_key = "adaptive_ids_secret_key"

DATABASE = "ids_database.db"


# =========================================================
# DATABASE STATISTICS
# =========================================================

def get_statistics():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM packet_logs")
    total_packets = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM packet_logs WHERE result = 'NORMAL'"
    )
    normal_packets = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM packet_logs WHERE result = 'ATTACK'"
    )
    suspicious_packets = cursor.fetchone()[0]

    connection.close()

    return total_packets, normal_packets, suspicious_packets


# =========================================================
# RECENT PACKETS
# =========================================================

def get_recent_packets(limit=10):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_length,
            anomaly_score,
            result,
            detection_time
        FROM packet_logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    packets = cursor.fetchall()

    connection.close()

    return packets


# =========================================================
# TRAFFIC DATA FOR CHART
# =========================================================

def get_traffic_data():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            detection_time,
            COUNT(*) AS packet_count
        FROM packet_logs
        GROUP BY detection_time
        ORDER BY detection_time DESC
        LIMIT 20
    """)

    rows = cursor.fetchall()

    connection.close()

    rows.reverse()

    return rows


# =========================================================
# AI THREAT EXPLANATION
# =========================================================

def explain_threat(packet):

    packet_length = packet[5]
    anomaly_score = packet[6]
    destination_port = packet[4]
    protocol = packet[2]

    reasons = []

    if anomaly_score >= 10:

        reasons.append(
            "Very high anomaly score"
        )

    elif anomaly_score >= 3:

        reasons.append(
            "High anomaly score"
        )

    if packet_length > 1500:

        reasons.append(
            "Unusually large packet"
        )

    if destination_port in [21, 22, 23, 3389]:

        reasons.append(
            "Sensitive destination port"
        )

    if protocol not in [6, 17]:

        reasons.append(
            "Unusual network protocol"
        )

    if not reasons:

        reasons.append(
            "Traffic pattern differs from normal baseline"
        )

    return ", ".join(reasons)


# =========================================================
# LOGIN
# =========================================================

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]

        password = request.form["password"]

        if username == "admin" and password == "admin123":

            session["logged_in"] = True

            return redirect("/dashboard")

        else:

            return render_template(
                "login.html",
                error="Invalid username or password"
            )

    return render_template("login.html")


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not session.get("logged_in"):

        return redirect("/")

    total, normal, suspicious = get_statistics()

    packets = get_recent_packets(10)

    return render_template(
        "dashboard.html",
        total=total,
        normal=normal,
        suspicious=suspicious,
        packets=packets
    )


# =========================================================
# THREATS PAGE
# =========================================================

@app.route("/threats")
def threats():

    if not session.get("logged_in"):

        return redirect("/")

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_length,
            anomaly_score,
            result,
            detection_time
        FROM packet_logs
        WHERE result = 'ATTACK'
        ORDER BY id DESC
        LIMIT 100
    """)

    threats = cursor.fetchall()

    connection.close()


    # =====================================================
    # AI EXPLANATION FOR EACH THREAT
    # =====================================================

    threat_data = []

    for packet in threats:

        reason = explain_threat(packet)

        threat_data.append(
            packet + (reason,)
        )


    total, normal, suspicious = get_statistics()

    return render_template(
        "threats.html",
        threats=threat_data,
        suspicious=suspicious
    )


# =========================================================
# PACKET LOGS PAGE
# =========================================================

@app.route("/packet-logs")
def packet_logs():

    if not session.get("logged_in"):

        return redirect("/")

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_length,
            anomaly_score,
            result,
            detection_time
        FROM packet_logs
        ORDER BY id DESC
        LIMIT 200
    """)

    packets = cursor.fetchall()

    connection.close()

    total, normal, suspicious = get_statistics()

    return render_template(
        "packet_logs.html",
        packets=packets,
        total=total,
        normal=normal,
        suspicious=suspicious
    )


# =========================================================
# LIVE PACKETS API
# =========================================================

@app.route("/api/live-packets")
def live_packets():

    if not session.get("logged_in"):

        return {"error": "Unauthorized"}, 401

    packets = get_recent_packets(20)

    data = []

    for packet in packets:

        data.append({

            "source_ip": packet[0],

            "destination_ip": packet[1],

            "protocol": packet[2],

            "source_port": packet[3],

            "destination_port": packet[4],

            "packet_length": packet[5],

            "anomaly_score": round(
                packet[6],
                2
            ),

            "result": packet[7],

            "detection_time": packet[8]

        })

    return data


# =========================================================
# TRAFFIC CHART API
# =========================================================

@app.route("/api/traffic-data")
def traffic_data():

    if not session.get("logged_in"):

        return {"error": "Unauthorized"}, 401

    rows = get_traffic_data()

    data = []

    for row in rows:

        data.append({

            "time": row[0],

            "packets": row[1]

        })

    return data


# =========================================================
# START FLASK
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )