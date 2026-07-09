import os
import asyncio
from fastapi import FastAPI, Request, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse

# Import our modular structural engines
from analyzer import analyze_submission
from edr_monitor import scan_and_enforce
from fw_manager import ban_ip, unban_ip, get_blacklist, init_db

app = FastAPI(title="Project Jinda Security Ecosystem")

SIEM_LOG_FILE = "jinda_siem.log"

# Initialize database on application startup
@app.on_event("startup")
async def startup_event():
    init_db()
    # Launch Pillar 2 background watchdog
    async def edr_watchdog_loop():
        while True:
            scan_and_enforce()
            await asyncio.sleep(3)
    asyncio.create_task(edr_watchdog_loop())


# --- MASTER HTML DASHBOARD THEME ---
def render_dashboard(content_view: str) -> str:
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Project Jinda Unified Control Center</title>
        <style>
            body {{ font-family: 'Ubuntu', Arial, sans-serif; background-color: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }}
            .container {{ max-width: 1200px; margin: auto; }}
            h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; margin-bottom: 20px; }}
            .nav {{ margin-bottom: 20px; background-color: #1e293b; padding: 12px; border-radius: 6px; border: 1px solid #334155; }}
            .nav a {{ color: #38bdf8; text-decoration: none; font-weight: bold; }}
            .grid-top {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }}
            .grid-bottom {{ display: grid; grid-template-columns: 1fr; gap: 20px; }}
            .card {{ background-color: #1e293b; padding: 22px; border-radius: 8px; border: 1px solid #334155; box-sizing: border-box; }}
            .card h3 {{ color: #f8fafc; margin-top: 0; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-bottom: 15px; }}
            textarea {{ width: 100%; height: 110px; background-color: #0f172a; color: #4ade80; border: 1px solid #475569; padding: 10px; border-radius: 4px; font-family: monospace; box-sizing: border-box; }}
            .btn {{ background-color: #0ea5e9; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; font-weight: bold; }}
            .btn:hover {{ background-color: #0284c7; }}
            .btn-danger {{ background-color: #ef4444; padding: 5px 10px; font-size: 12px; }}
            .btn-danger:hover {{ background-color: #dc2626; }}
            .terminal-view {{ background-color: #020617; border-left: 4px solid #f43f5e; color: #f1f5f9; font-family: monospace; padding: 15px; border-radius: 4px; height: 180px; overflow-y: auto; font-size: 11px; white-space: pre-wrap; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #334155; }}
            th {{ background-color: #0f172a; color: #38bdf8; }}
            input[type="text"] {{ background-color: #0f172a; color: white; border: 1px solid #475569; padding: 8px; border-radius: 4px; margin-right: 10px; width: 200px; }}
            .alert-box {{ padding: 12px; border-radius: 6px; margin-top: 15px; font-weight: bold; }}
            .danger {{ background-color: #7f1d1d; color: #fca5a5; border: 1px solid #f87171; }}
            .safe {{ background-color: #064e3b; color: #6ee7b7; border: 1px solid #34d399; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Project Jinda: Unified Security Operations Center (SOC)</h1>
            <div class="nav"><a href="/">🔄 Refresh Dashboard Monitor</a></div>
            {content_view}
        </div>
    </body>
    </html>
    """

# --- GET ROUTE: Render Complete Dashboard ---
@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    # 1. Fetch EDR Terminal Logs
    log_content = "🟢 EDR Monitor Active: Kernel tracking hooks live...\n"
    if os.path.exists(SIEM_LOG_FILE):
        with open(SIEM_LOG_FILE, "r") as f:
            log_content += "".join(f.readlines()[-10:])
            
    # 2. Fetch Firewall Blacklist rows from SQLite DB
    blacklist_data = get_blacklist()
    table_rows = ""
    for row in blacklist_data:
        table_rows += f"""
        <tr>
            <td>🔴 <code>{row[0]}</code></td>
            <td>{row[1]}</td>
            <td>{row[2]}</td>
            <td>
                <form action="/unban" method="post" style="margin:0;">
                    <input type="hidden" name="ip_address" value="{row[0]}">
                    <button type="submit" class="btn btn-danger">Drop Rule</button>
                </form>
            </td>
        </tr>
        """
    if not table_rows:
        table_rows = "<tr><td colspan='4' style='text-align:center; color:#64748b;'>No Active Rules Deployed. Network Unrestricted.</td></tr>"

    master_view = f"""
    <div class="grid-top">
        <div class="card">
            <h3>Pillar 1: Phishing Mail Parser</h3>
            <form action="/analyze" method="post">
                <textarea name="raw_input" placeholder="Paste full raw email or threat vectors here..."></textarea>
                <button type="submit" class="btn" style="margin-top:10px;">Run Heuristic Scan</button>
            </form>
        </div>
        
        <div class="card">
            <h3>Pillar 2: EDR Live SIEM Logs</h3>
            <div class="terminal-view">{log_content}</div>
        </div>
    </div>
    
    <div class="grid-bottom">
        <div class="card">
            <h3>Pillar 3: Orchestrated Firewall Database & IPS Rules</h3>
            <p style="color:#94a3b8; font-size:14px; margin-top:0;">Manually propagate localized threat blocks or let automated actions feed straight into the Linux kernel pipeline.</p>
            
            <form action="/ban" method="post" style="margin-bottom: 20px;">
                <input type="text" name="ip_address" placeholder="Target Threat IP (e.g., 185.220.101.5)" required>
                <input type="text" name="reason" placeholder="Reason (e.g., Brute Force Attempt)" style="width:280px;" required>
                <button type="submit" class="btn">Deploy Kernel Ban</button>
            </form>
            
            <table>
                <thead>
                    <tr><th>Banned Target IP</th><th>Threat Classification Reason</th><th>Timestamp Issued</th><th>Action</th></tr>
                </thead>
                <tbody>{table_rows}</tbody>
            </table>
        </div>
    </div>
    """
    return HTMLResponse(content=render_dashboard(master_view))

# --- POST ROUTE: Handle Pillar 1 Scans ---
@app.post("/analyze", response_class=HTMLResponse)
async def handle_analysis(raw_input: str = Form(...)):
    report = analyze_submission(raw_input)
    alert_class = "danger" if report["score"] >= 50 else "safe"
    keywords_list = "".join([f"<li><code>{kw}</code></li>" for kw in report["keywords_found"]]) or "<li>None</li>"
    urls_list = "".join([f"<li>{url}</li>" for url in report["defanged_urls"]]) or "<li>None</li>"
    
    report_html = f"""
    <div class="card">
        <h3>Pillar 1 Analysis Metrics Output</h3>
        <div class="alert-box {alert_class}">Threat Verdict: {report["verdict"]} | Score: {report["score"]} Points</div>
        <h4>Technical Audit Findings:</h4><ul><li>DMARC Alignment Failure Flag: {report["dmarc_fail"]}</li></ul>
        <h4>Keywords Found:</h4><ul>{keywords_list}</ul>
        <h4>Defanged URLs:</h4><ul>{urls_list}</ul>
        <a href="/"><button class="btn">Return to Control Center</button></a>
    </div>
    """
    return HTMLResponse(content=render_dashboard(report_html))

# --- POST ROUTE: Handle Manual/Automated Banning ---
@app.post("/ban")
async def handle_ban(ip_address: str = Form(...), reason: str = Form(...)):
    ban_ip(ip_address, reason)
    return RedirectResponse(url="/", status_code=303)

# --- POST ROUTE: Handle Unbanning / Dropping Rules ---
@app.post("/unban")
async def handle_unban(ip_address: str = Form(...)):
    unban_ip(ip_address)
    return RedirectResponse(url="/", status_code=303)