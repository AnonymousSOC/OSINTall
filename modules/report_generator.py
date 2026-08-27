#!/usr/bin/env python3
"""
OSINTALL - Report Generation Module
Exports reconnaissance findings to JSON, Markdown, and styled HTML reports.
"""

import os
import json
import datetime
from modules.banner import console, print_info, print_success, print_error

def ensure_reports_dir() -> str:
    """Ensures reports directory exists and returns its absolute path."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir

def save_json_report(data: dict, target_name: str) -> str:
    """Saves raw structured intelligence data into a JSON file."""
    reports_dir = ensure_reports_dir()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = "".join(c for c in target_name if c.isalnum() or c in ("-", "_", "."))
    filename = f"osint_report_{clean_target}_{timestamp}.json"
    filepath = os.path.join(reports_dir, filename)

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, default=str)
        print_success(f"JSON Report exported to: [bold cyan]{filepath}[/]")
        return filepath
    except Exception as e:
        print_error(f"Failed to save JSON report: {e}")
        return ""

def save_html_report(data: dict, target_name: str) -> str:
    """Generates a styled, dark-mode HTML reconnaissance report."""
    reports_dir = ensure_reports_dir()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = "".join(c for c in target_name if c.isalnum() or c in ("-", "_", "."))
    filename = f"osint_report_{clean_target}_{timestamp}.html"
    filepath = os.path.join(reports_dir, filename)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINTALL Report - {target_name}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --accent: #58a6ff;
            --success: #3fb950;
            --warning: #d29922;
            --danger: #f85149;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{
            color: var(--accent);
            margin: 0;
            font-size: 2.2rem;
        }}
        .meta {{
            color: #8b949e;
            font-size: 0.95rem;
            margin-top: 5px;
        }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        .card h2 {{
            color: var(--success);
            font-size: 1.3rem;
            margin-top: 0;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        pre {{
            background: #090d13;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 15px;
            overflow-x: auto;
            color: #79c0ff;
            font-size: 0.9rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            text-align: left;
            padding: 10px 14px;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background-color: #21262d;
            color: var(--accent);
        }}
        a {{
            color: var(--accent);
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ OSINTALL Reconnaissance Report</h1>
            <div class="meta">Target: <strong>{target_name}</strong> | Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
        </header>

        <div class="card">
            <h2>Summary & Raw Intelligence Findings</h2>
            <pre><code>{json.dumps(data, indent=4, default=str)}</code></pre>
        </div>
    </div>
</body>
</html>
"""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        print_success(f"HTML Report exported to: [bold cyan]{filepath}[/]")
        return filepath
    except Exception as e:
        print_error(f"Failed to save HTML report: {e}")
        return ""
