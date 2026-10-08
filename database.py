import sqlite3


DATABASE = "ids_database.db"


def create_database():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packet_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol INTEGER,
            source_port INTEGER,
            destination_port INTEGER,
            packet_length INTEGER,
            anomaly_score REAL,
            result TEXT,
            detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


def save_packet(
    source_ip,
    destination_ip,
    protocol,
    source_port,
    destination_port,
    packet_length,
    anomaly_score,
    result
):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO packet_logs (
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_length,
            anomaly_score,
            result
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        packet_length,
        anomaly_score,
        result
    ))

    connection.commit()
    connection.close()


def get_recent_packets(limit=20):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM packet_logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    packets = cursor.fetchall()

    connection.close()

    return packets


# Create database when this file is run
if __name__ == "__main__":
    create_database()
    print("IDS database created successfully.")