import json
import os
from datetime import datetime


class ReportGenerator:

    def __init__(self, output_folder="output"):
        self.output_folder = output_folder
        os.makedirs(output_folder, exist_ok=True)

    # ------------------------------------------------
    # Generate HTML report
    # ------------------------------------------------
    def generate_html(self, data):

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.output_folder, f"bensam_report_{timestamp}.html")

        total_hosts = len(data)

        critical = sum(1 for h in data if h.get("risk_level") == "CRITICAL")
        high = sum(1 for h in data if h.get("risk_level") == "HIGH")
        medium = sum(1 for h in data if h.get("risk_level") == "MEDIUM")
        low = sum(1 for h in data if h.get("risk_level") == "LOW")

        html = f"""
        <html>
        <head>
        <title>BENSAM Vulnerability Report</title>
        <style>
        body {{font-family: Arial; margin:40px}}
        h1 {{color:#2c3e50}}
        table {{border-collapse: collapse; width:100%}}
        th,td {{border:1px solid #ccc; padding:8px}}
        th {{background:#f4f4f4}}
        </style>
        </head>

        <body>

        <h1>BENSAM Network Security Report</h1>

        <h2>Executive Summary</h2>

        <p>Total Hosts Scanned: {total_hosts}</p>
        <p>Critical Risk Hosts: {critical}</p>
        <p>High Risk Hosts: {high}</p>
        <p>Medium Risk Hosts: {medium}</p>
        <p>Low Risk Hosts: {low}</p>

        <h2>Host Risk Overview</h2>

        <table>
        <tr>
        <th>Host IP</th>
        <th>Open Services</th>
        <th>Risk Score</th>
        <th>Risk Level</th>
        </tr>
        """

        for host in data:

            services = ", ".join(host.get("services", []))

            html += f"""
            <tr>
            <td>{host.get("ip")}</td>
            <td>{services}</td>
            <td>{host.get("risk_score")}</td>
            <td>{host.get("risk_level")}</td>
            </tr>
            """

        html += "</table>"

        html += "<h2>Detected Vulnerabilities</h2>"

        for host in data:

            vulns = host.get("vulnerability_intel", [])

            if not vulns:
                continue

            html += f"<h3>Host {host.get('ip')}</h3>"
            html += "<table>"
            html += "<tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Description</th></tr>"

            for v in vulns:

                html += f"""
                <tr>
                <td>{v.get('cve')}</td>
                <td>{v.get('cvss_score')}</td>
                <td>{v.get('severity')}</td>
                <td>{v.get('description')}</td>
                </tr>
                """

            html += "</table>"

        html += "</body></html>"

        with open(report_file, "w", encoding="utf-8") as f:
            f.write(html)

        return report_file


    # ------------------------------------------------
    # Save JSON report (structured data)
    # ------------------------------------------------
    def generate_json(self, data):

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.output_folder, f"bensam_report_{timestamp}.json")

        with open(report_file, "w") as f:
            json.dump(data, f, indent=4)

        return report_file