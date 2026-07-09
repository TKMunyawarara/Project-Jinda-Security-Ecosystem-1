import sqlite3
import subprocess
import re

DB_FILE = "jinda_security.db"

def init_db():
    """Initializes the Threat Intelligence SQLite Database tables."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Create a table to hold our active firewall blocks
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS firewall_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def execute_fw_command(cmd_list: list) -> bool:
    """Executes a system shell command safely using Python's subprocess library."""
    try:
        # Run command with a 3-second timeout to prevent stalling the web server
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=3)
        return result.returncode == 0
    except Exception:
        return False

def ban_ip(ip_address: str, reason: str) -> str:
    """Inserts an IP into the database and issues a kernel-level firewall deny rule."""
    # Strict regex check to ensure the input is a valid IPv4 address (prevents command injection)
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
        return "INVALID_IP_FORMAT"

    # 1. Sync to Local SQLite Threat Intelligence Database
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO firewall_blacklist (ip_address, reason) VALUES (?, ?)", (ip_address, reason))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return "ALREADY_BANNED"
    conn.close()

    # 2. Sync to Linux Firewall Kernel (ufw)
    # Equivalent to typing: sudo ufw deny from [IP] to any
    cmd = ["sudo", "ufw", "deny", "from", ip_address, "to", "any"]
    success = execute_fw_command(cmd)
    
    return "SUCCESS" if success else "DATABASE_ONLY_MOCK_ENV"

def unban_ip(ip_address: str) -> bool:
    """Removes an IP from the database and deletes its active firewall rule."""
    # 1. Remove from SQLite Database
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM firewall_blacklist WHERE ip_address = ?", (ip_address,))
    conn.commit()
    conn.close()

    # 2. Remove from Linux Firewall Kernel (ufw delete deny...)
    cmd = ["sudo", "ufw", "delete", "deny", "from", ip_address, "to", "any"]
    return execute_fw_command(cmd)

def get_blacklist() -> list:
    """Retrieves all active threat actor IPs from our database repository."""
    init_db()  # Make sure table exists
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, reason, timestamp FROM firewall_blacklist ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows