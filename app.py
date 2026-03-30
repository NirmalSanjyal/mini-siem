from flask import Flask, render_template
import sqlite3

app = Flask(__name__)
DB_FILE = "siem.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def dashboard():
    conn = get_db()
    events = conn.execute("SELECT * FROM events").fetchall()
    alerts = conn.execute("SELECT * FROM alerts").fetchall()
    conn.close()
    return render_template("dashboard.html", events=events, alerts=alerts)

if __name__ == "__main__":
    app.run(debug=True)