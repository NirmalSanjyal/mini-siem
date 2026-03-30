import re
import sqlite3
from collections import defaultdict

LOG_FILE = "logs/sample_auth.log"
DB_FILE = "siem.db"

LOG_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+\S+\s+'
    r'(?P<event>Failed password|Accepted password)'
    r'.+?(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)'
)

BRUTE_FORCE_THRESHOLD = 3

def init_db(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            event TEXT,
            user TEXT,
            ip TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            count INTEGER,
            severity TEXT
        )
    ''')
    conn.commit()

def parse_logs(filepath):
    events = []
    with open(filepath, "r") as f:
        for line in f:
            match = LOG_PATTERN.search(line)
            if match:
                events.append({
                    "time": match.group("time"),
                    "event": match.group("event"),
                    "user": match.group("user"),
                    "ip": match.group("ip"),
                })
    return events

def save_events(conn, events):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM events")
    for e in events:
        cursor.execute(
            "INSERT INTO events (time, event, user, ip) VALUES (?, ?, ?, ?)",
            (e["time"], e["event"], e["user"], e["ip"])
        )
    conn.commit()
    print(f"✅ Saved {len(events)} events to database.")

def detect_brute_force(events):
    failed_attempts = defaultdict(int)
    for e in events:
        if e["event"] == "Failed password":
            failed_attempts[e["ip"]] += 1

    alerts = []
    for ip, count in failed_attempts.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "ip": ip,
                "count": count,
                "severity": "HIGH" if count >= 5 else "MEDIUM"
            })
    return alerts

def save_alerts(conn, alerts):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    for a in alerts:
        cursor.execute(
            "INSERT INTO alerts (ip, count, severity) VALUES (?, ?, ?)",
            (a["ip"], a["count"], a["severity"])
        )
    conn.commit()
    print(f"✅ Saved {len(alerts)} alerts to database.")

def display_alerts(alerts):
    print(f"\n{'='*60}")
    print("🚨 ALERTS DETECTED")
    print(f"{'='*60}")
    if not alerts:
        print("No threats detected.")
    else:
        for a in alerts:
            print(f"[{a['severity']}] Brute Force from IP: {a['ip']} — {a['count']} failed attempts")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    conn = sqlite3.connect(DB_FILE)
    init_db(conn)

    events = parse_logs(LOG_FILE)
    save_events(conn, events)

    alerts = detect_brute_force(events)
    save_alerts(conn, alerts)
    display_alerts(alerts)

    conn.close()