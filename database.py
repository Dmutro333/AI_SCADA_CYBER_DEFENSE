import os
import sqlite3
import json
from datetime import datetime


DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "scada_system.db")


def get_connection():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS event_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_time TEXT NOT NULL,
        user TEXT,
        role TEXT,
        event_type TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sensor_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        temperature REAL,
        pressure REAL,
        turbine_rpm REAL,
        power_output REAL,
        vibration REAL,
        water_level REAL,
        load_percent REAL,
        system_status TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_time TEXT NOT NULL,
        attack_type TEXT,
        source_ip TEXT,
        source TEXT,
        target TEXT,
        severity TEXT,
        description TEXT,
        impact TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS defense_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action_time TEXT NOT NULL,
        safe_mode INTEGER,
        isolated_plc INTEGER,
        load_reduced INTEGER,
        blocked_ips TEXT,
        actions TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        risk_time TEXT NOT NULL,
        risk_level TEXT,
        risk_score REAL,
        factors TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS correlated_incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_time TEXT NOT NULL,
        incident_level TEXT,
        incident_score REAL,
        findings TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_trail (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        audit_time TEXT NOT NULL,
        username TEXT,
        role TEXT,
        module TEXT,
        action TEXT,
        result TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        notify_time TEXT NOT NULL,
        level TEXT,
        title TEXT,
        message TEXT
    )
    """)


    # Compatibility tables for the final diploma structure.
    # These tables mirror the names used in the explanatory note and appendices.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        attack_type TEXT,
        source_ip TEXT,
        source TEXT,
        target TEXT,
        severity TEXT,
        description TEXT,
        impact TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        event_type TEXT,
        severity TEXT,
        description TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ai_decisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        model_name TEXT,
        predicted_class TEXT,
        confidence REAL,
        risk_score REAL,
        reasons TEXT,
        recommendation TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        risk_level TEXT,
        risk_score REAL,
        factors TEXT,
        related_attack_type TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        user TEXT,
        role TEXT,
        module TEXT,
        event_type TEXT,
        severity TEXT,
        description TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        report_type TEXT,
        title TEXT,
        file_path TEXT,
        summary TEXT
    )
    """)

    default_users = [
        ("admin", "admin123", "Admin"),
        ("operator", "operator123", "Operator"),
        ("analyst", "analyst123", "Analyst"),
    ]

    for username, password, role in default_users:
        cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES (?, ?, ?)
        """, (username, password, role))

    conn.commit()
    conn.close()


def check_user(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT username, role
    FROM users
    WHERE username = ? AND password = ?
    """, (username, password))
    result = cursor.fetchone()
    conn.close()
    return result


def get_users():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT username, role
        FROM users
        ORDER BY id ASC
    """)

    users = cursor.fetchall()
    conn.close()

    return users


def add_user(username, password, role):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR IGNORE INTO users (username, password, role)
    VALUES (?, ?, ?)
    """, (username, password, role))
    conn.commit()
    conn.close()


def add_event_log(user, role, event_type, description, severity="INFO"):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
    INSERT INTO event_logs
    (event_time, user, role, event_type, description, severity)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        now,
        user,
        role,
        event_type,
        description,
        severity,
    ))
    cursor.execute("""
    INSERT INTO system_logs
    (timestamp, user, role, module, event_type, severity, description)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        now,
        user,
        role,
        "SYSTEM",
        event_type,
        severity,
        description,
    ))
    conn.commit()
    conn.close()


def get_event_logs(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT event_time, user, role, event_type, description, severity
    FROM event_logs
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    logs = cursor.fetchall()
    conn.close()
    return logs


def add_sensor_data(temperature, pressure, turbine_rpm, power_output, vibration, water_level, load_percent, system_status):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO sensor_data
    (timestamp, temperature, pressure, turbine_rpm, power_output, vibration, water_level, load_percent, system_status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        temperature,
        pressure,
        turbine_rpm,
        power_output,
        vibration,
        water_level,
        load_percent,
        system_status,
    ))
    conn.commit()
    conn.close()


def add_attack_record(attack):
    conn = get_connection()
    cursor = conn.cursor()
    attack_time = attack.get("time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    attack_type = attack.get("attack_type", attack.get("type", "UNKNOWN"))
    source_ip = attack.get("source_ip", "0.0.0.0")
    source = attack.get("source", "Unknown")
    target = attack.get("target", "SCADA/ICS")
    severity = attack.get("severity", "MEDIUM")
    description = attack.get("description", "Cyberattack scenario")
    impact = attack.get("impact", "Security event generated")
    cursor.execute("""
    INSERT INTO attacks
    (attack_time, attack_type, source_ip, source, target, severity, description, impact)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        attack_time,
        attack_type,
        source_ip,
        source,
        target,
        severity,
        description,
        impact,
    ))
    cursor.execute("""
    INSERT INTO attack_logs
    (timestamp, attack_type, source_ip, source, target, severity, description, impact)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        attack_time,
        attack_type,
        source_ip,
        source,
        target,
        severity,
        description,
        impact,
    ))
    conn.commit()
    conn.close()


def get_attack_records(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT attack_time, attack_type, source_ip, source, target, severity, description, impact
    FROM attacks
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    records = cursor.fetchall()
    conn.close()
    return records


def add_defense_record(defense_result):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO defense_actions
    (action_time, safe_mode, isolated_plc, load_reduced, blocked_ips, actions)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        defense_result["time"],
        int(defense_result["safe_mode"]),
        int(defense_result["isolated_plc"]),
        int(defense_result["load_reduced"]),
        ", ".join(defense_result["blocked_ips"]),
        "; ".join(defense_result["actions"]),
    ))
    conn.commit()
    conn.close()


def get_defense_records(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT action_time, safe_mode, isolated_plc, load_reduced, blocked_ips, actions
    FROM defense_actions
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    records = cursor.fetchall()
    conn.close()
    return records


def add_risk_record(risk_result):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_level = risk_result.get("risk_level", "LOW")
    risk_score = risk_result.get("risk_score", 0)
    factors = risk_result.get("factors", [])
    factors_text = "; ".join(factors) if isinstance(factors, (list, tuple)) else str(factors)
    related_attack_type = risk_result.get("attack_type", risk_result.get("related_attack_type", ""))
    cursor.execute("""
    INSERT INTO risk_scores
    (risk_time, risk_level, risk_score, factors)
    VALUES (?, ?, ?, ?)
    """, (
        now,
        risk_level,
        risk_score,
        factors_text,
    ))
    cursor.execute("""
    INSERT INTO risk_events
    (timestamp, risk_level, risk_score, factors, related_attack_type)
    VALUES (?, ?, ?, ?, ?)
    """, (
        now,
        risk_level,
        risk_score,
        factors_text,
        related_attack_type,
    ))
    conn.commit()
    conn.close()


def get_risk_records(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT risk_time, risk_level, risk_score, factors
    FROM risk_scores
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    records = cursor.fetchall()
    conn.close()
    return records


def add_correlated_incident(incident):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO correlated_incidents
    (incident_time, incident_level, incident_score, findings)
    VALUES (?, ?, ?, ?)
    """, (
        incident["time"],
        incident["incident_level"],
        incident["incident_score"],
        "; ".join(incident["findings"]),
    ))
    conn.commit()
    conn.close()


def get_correlated_incidents(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT incident_time, incident_level, incident_score, findings
    FROM correlated_incidents
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    records = cursor.fetchall()
    conn.close()
    return records


def add_audit_record(username, role, module, action, result):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO audit_trail
    (audit_time, username, role, module, action, result)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        username,
        role,
        module,
        action,
        result,
    ))
    conn.commit()
    conn.close()


def get_audit_records(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT audit_time, username, role, module, action, result
    FROM audit_trail
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    records = cursor.fetchall()
    conn.close()
    return records


def add_notification_record(notification):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO notifications
    (notify_time, level, title, message)
    VALUES (?, ?, ?, ?)
    """, (
        notification["time"],
        notification["level"],
        notification["title"],
        notification["message"],
    ))
    conn.commit()
    conn.close()


def get_notification_records(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT notify_time, level, title, message
    FROM notifications
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    records = cursor.fetchall()
    conn.close()
    return records


def clear_notification_records():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notifications")
    conn.commit()
    conn.close()



def add_traffic_log(source_ip="0.0.0.0", destination_ip="SCADA_SERVER", protocol="TCP",
                    event_type="NETWORK_EVENT", severity="INFO", description="Network event"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO traffic_logs
    (timestamp, source_ip, destination_ip, protocol, event_type, severity, description)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        source_ip,
        destination_ip,
        protocol,
        event_type,
        severity,
        description,
    ))
    conn.commit()
    conn.close()


def get_traffic_logs(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT timestamp, source_ip, destination_ip, protocol, event_type, severity, description
    FROM traffic_logs
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    records = cursor.fetchall()
    conn.close()
    return records


def add_ai_decision(decision):
    conn = get_connection()
    cursor = conn.cursor()
    reasons = decision.get("reasons", [])
    reasons_text = "; ".join(reasons) if isinstance(reasons, (list, tuple)) else str(reasons)
    cursor.execute("""
    INSERT INTO ai_decisions
    (timestamp, model_name, predicted_class, confidence, risk_score, reasons, recommendation)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        decision.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        decision.get("model_used", decision.get("model_name", "RandomForest+Rules")),
        decision.get("label", decision.get("predicted_class", "UNKNOWN")),
        float(decision.get("confidence", 0)),
        float(decision.get("risk_score", decision.get("confidence", 0))),
        reasons_text,
        decision.get("recommendation", ""),
    ))
    conn.commit()
    conn.close()


def get_ai_decisions(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT timestamp, model_name, predicted_class, confidence, risk_score, reasons, recommendation
    FROM ai_decisions
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    records = cursor.fetchall()
    conn.close()
    return records


def add_report_record(report_type="TEST_REPORT", title="AI SCADA Cyber Defense Report",
                      file_path="", summary=""):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO reports
    (created_at, report_type, title, file_path, summary)
    VALUES (?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        report_type,
        title,
        file_path,
        summary,
    ))
    conn.commit()
    conn.close()


def get_report_records(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT created_at, report_type, title, file_path, summary
    FROM reports
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    records = cursor.fetchall()
    conn.close()
    return records


def get_system_statistics():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM sensor_data")
    sensor_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM attacks")
    attack_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM defense_actions")
    defense_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM event_logs WHERE severity IN ('HIGH', 'CRITICAL')")
    critical_events = cursor.fetchone()[0]

    cursor.execute("""
    SELECT system_status
    FROM sensor_data
    ORDER BY id DESC
    LIMIT 1
    """)
    last_status_row = cursor.fetchone()
    last_status = last_status_row[0] if last_status_row else "UNKNOWN"

    conn.close()

    return {
        "sensor_count": sensor_count,
        "attack_count": attack_count,
        "defense_count": defense_count,
        "critical_events": critical_events,
        "last_status": last_status,
    }


def cleanup_old_logs(days=30):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    DELETE FROM event_logs
    WHERE event_time < datetime('now', ?)
    """, (f"-{days} day",))
    conn.commit()
    conn.close()


def reset_database_file():
    """
    Обережно: повністю видаляє SQLite-файл.
    Використовувати тільки для тестового перезапуску проєкту.
    """
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
