import subprocess
import re
import requests
import pdfkit
import logging
import time


# Constants
NIST_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TARGET_IP = "127.0.0.1"
TARGET_URL = f"http://{TARGET_IP}"

# Risky open ports
RISKY_PORTS = {
    "21": "FTP - May allow anonymous login",
    "23": "Telnet - Unencrypted communication",
    "25": "SMTP - Open relay risks",
    "3306": "MySQL - Potential for SQL injection"
}

# Nikto Vulnerability Mapping
NIKTO_VULN_MAPPING = {
    "X-Frame-Options": "Clickjacking vulnerability",
    "X-Content-Type-Options": "MIME sniffing vulnerability",
    "Server version": "Server information leakage",
    "PHP backdoor file manager": "Possible remote code execution"
}

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ** Run Nmap Scan **
def run_nmap():
    logging.info("[*] Running Nmap scan...")
    cmd = ["nmap", "-sV", "-T4", TARGET_IP]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"[-] Error running Nmap: {e.stderr}")
        return None


# ** Run Nikto Scan **
def run_nikto():
    """
    Runs Nikto on the target and extracts vulnerabilities.
    - Captures all output first.
    - Then, processes only the vulnerabilities, ignoring metadata.
    """
    logging.info("[*] Running Nikto scan...")
    nikto_config = "C:\\Nikto\\program\\nikto.conf"  # Adjust path if necessary
    cmd = [
        "perl", "nikto.pl", "-h", TARGET_URL, 
         nikto_config
    ]

    try:
        # Run Nikto and capture all output at once
        result = subprocess.run(cmd, capture_output=True, text=True, cwd="C:\\nikto", timeout=300)

        # Check if Nikto produced any output
        if result.returncode != 0 or not result.stdout:
            logging.error("[-] Nikto scan failed or returned no output.")
            return None

        # Split the output into lines
        nikto_output = result.stdout.split("\n")
        findings = []

        # Process each line to extract vulnerabilities
        for line in nikto_output:
            line = line.strip()
            if line.startswith("+"):  # Only include lines starting with "+"
                findings.append(line)

        # Return the findings as a single string
        return "\n".join(findings) if findings else "No vulnerabilities found."

    except subprocess.TimeoutExpired:
        logging.warning("[!] Nikto scan timed out after 300 seconds.")
        return "Scan timed out."
    except subprocess.SubprocessError as e:
        logging.error(f"[-] Error running Nikto: {str(e)}")
        return None
    """
    Runs Nikto on the target and extracts vulnerabilities.
    - Captures all output first.
    - Then, processes only the vulnerabilities, ignoring metadata.
    """
    logging.info("[*] Running Nikto scan...")
    nikto_config = "C:\\Nikto\\program\\nikto.conf.default"  # Keep original path
    cmd = [
        "perl", "nikto.pl", "-h", TARGET_URL, 
        "-config", nikto_config, "-Tuning", "4,9", "-nolookup", "-nossl",
        "-Plugins", "apache", "-maxtime", "300"
    ]

    try:
        # Run Nikto and capture all output at once
        result = subprocess.run(cmd, capture_output=True, text=True, cwd="C:\\nikto", timeout=30)

        nikto_output = result.stdout.split("\n")  # Split into lines
        findings = []
        found_server = False
        start_time = time.time()

        for line in nikto_output:
            line = line.strip()

            # Wait for "+ Server:" to start capturing findings
            if "+ Server:" in line:
                found_server = True
                start_time = time.time()  # Start 20s timer

            if found_server:
                findings.append(line)

            # Stop collecting after 20 seconds
            if found_server and (time.time() - start_time) >= 20:
                break

        return "\n".join(findings) if findings else "No vulnerabilities found."

    except subprocess.TimeoutExpired:
        logging.warning("[!] Nikto scan timed out after 30 seconds.")
        return "Scan timed out."
    except subprocess.SubprocessError as e:
        logging.error(f"[-] Error running Nikto: {str(e)}")
        return None
    """
    Runs Nikto on the target and extracts vulnerabilities.
    - Starts reading **after** the "+ Server:" line appears.
    - Collects findings for **20 seconds** after detecting the server line.
    """
    logging.info("[*] Running Nikto scan...")
    nikto_config = "C:\\Nikto\\program\\nikto.conf.default"  # Keep original path
    cmd = [
        "perl", "nikto.pl", "-h", TARGET_URL, 
        "-config", nikto_config, "-Tuning", "4,9", "-nolookup", "-nossl",
        "-Plugins", "apache", "-maxtime", "300"
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd="C:\\nikto"
        )

        nikto_output = []
        found_server = False
        start_time = None

        while True:
            line = process.stdout.readline()
            if not line:
                break  # Stop if process is done

            line = line.strip()

            # Check for "+ Server:" line
            if "+ Server:" in line:
                found_server = True
                start_time = time.time()  # Start 20s timer

            # Start saving output only after finding the server line
            if found_server:
                nikto_output.append(line)

            # Stop collecting after 20 seconds
            if found_server and (time.time() - start_time) >= 20:
                break

        # Ensure the process is terminated
        process.terminate()

        return "\n".join(nikto_output) if nikto_output else "No vulnerabilities found."

    except subprocess.SubprocessError as e:
        logging.error(f"[-] Error running Nikto: {str(e)}")
        return None

    """
    Runs Nikto on the target with a 30-second timeout.
    Waits 20 seconds before reading output to avoid metadata.
    """
    logging.info("[*] Running Nikto scan...")
    nikto_config = "C:\\Nikto\\program\\nikto.conf"  # Keep original path
    cmd = [
        "perl", "nikto.pl", "-h", TARGET_URL, 
        "-config", nikto_config, "-Tuning", "4,9", "-nolookup", "-nossl",
        "-Plugins", "apache", "-maxtime", "300"
    ]
    
    try:
        # Start Nikto process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd="C:\\nikto"  # Keep original working directory
        )

        nikto_output = []
        start_time = time.time()

        # **Wait 20 seconds before capturing output to skip metadata**
        while time.time() - start_time < 20:
            time.sleep(1)  # Just let Nikto run

        # Now, read output for the remaining 10 seconds
        while time.time() - start_time < 30:
            line = process.stdout.readline()
            if not line:
                break
            nikto_output.append(line.strip())

        # Ensure the process is terminated after timeout
        process.terminate()

        # Extract actual vulnerabilities (ignore metadata)
        findings = [line for line in nikto_output if "/" in line or "vulnerable" in line.lower()]

        return "\n".join(findings) if findings else "No vulnerabilities found."

    except subprocess.SubprocessError as e:
        logging.error(f"[-] Error running Nikto: {str(e)}")
        return None

# ** Extract Apache Version from Nmap **
def extract_apache_version(nmap_output):
    match = re.search(r"Apache httpd ([\d.]+)", nmap_output)
    return match.group(1) if match else None

# ** Extract Open Ports from Nmap **
def extract_open_ports(nmap_output):
    ports = re.findall(r"(\d+)/tcp\s+open\s+([\w\d\s\.\(\)-]+)", nmap_output)
    return {port: service for port, service in ports}

# ** Extract Nikto Findings **
def extract_nikto_findings(nikto_output):
    """
    Extracts only relevant vulnerabilities from Nikto output, ignoring metadata.
    """
    findings = []
    
    for line in nikto_output.split("\n"):
        if line.startswith("+") and not any(keyword in line for keyword in ["Target", "Start Time", "End Time", "requests"]):
            findings.append(line.strip())

    print("[*] Extracted Nikto Findings:", findings)
    return findings

# ** Fetch CVEs from NIST API **
def fetch_cves_from_nist(queries):
    if not queries:
        return [{"id": "None", "description": "No valid queries provided for CVE lookup."}]
    
    query_string = " OR ".join(queries)
    params = {"keywordSearch": query_string, "resultsPerPage": 5}

    response = requests.get(NIST_API_URL, params=params)
    if response.status_code == 200:
        data = response.json()
        cves = [{"id": item["cve"]["id"], "description": item["cve"]["descriptions"][0]["value"]}
                for item in data.get("vulnerabilities", [])]
        
        if not cves:
            return [{"id": "None", "description": "No CVEs found for the given queries."}]
        
        return cves
    return [{"id": "Error", "description": "Failed to fetch CVEs from NIST API."}]



# ** Analyze Open Ports for Security Issues **
def analyze_open_ports(nmap_output):
    risk_assessment = {
        21: "High (FTP - often vulnerable to brute force attacks)",
        22: "Medium (SSH - secure if configured properly, but targeted)",
        80: "Medium (HTTP - potential for outdated web applications)",
        135: "High (Windows RPC - common attack vector for exploits like EternalBlue)",
        445: "High (SMB - vulnerable to ransomware and exploits like WannaCry)",
        3389: "High (RDP - often targeted for remote attacks)",
    }
    
    open_ports = re.findall(r"(\d+)/tcp\s+open\s+(\w+)", nmap_output)
    
    analyzed_ports = []
    for port, service in open_ports:
        port = int(port)
        risk = risk_assessment.get(port, "Low (No major known risks)")
        analyzed_ports.append(f"Port {port}: {service} - {risk}")

    return analyzed_ports

# ** Generate Security Report (PDF) **
def generate_report(nmap_output, nikto_output, apache_version, open_ports, port_findings, apache_cves, nikto_findings, nikto_cves):
    html_content = f"""
    <html>
    <head>
        <title>Web Server Security Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            h2 {{ color: red; }}
            .section {{ margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <h1>Web Server Security Assessment Report</h1>
        <hr>
        <div class="section">
            <h2>1. Nmap Scan Results</h2>
            <pre>{nmap_output}</pre>
        </div>
        <div class="section">
            <h2>2. Nikto Scan Results</h2>
            <pre>{nikto_output}</pre>
        </div>
        <div class="section">
            <h2>3. Apache Version Detected</h2>
            <p>Apache {apache_version}</p>
        </div>
        <div class="section">
            <h2>4. Open Ports Detected</h2>
            <ul>
    """

    for port, service in open_ports.items():
        html_content += f"<li>Port {port}: {service}</li>"

    html_content += """
            </ul>
        </div>
        <div class="section">
            <h2>5. Risky Open Ports</h2>
            <ul>
    """

    for finding in port_findings:
        html_content += f"<li>{finding}</li>"

    html_content += """
            </ul>
        </div>
        <div class="section">
            <h2>6. Apache CVEs from NIST</h2>
            <ul>
    """

    for cve in apache_cves:
        html_content += f"<li>{cve['id']}: {cve['description']}</li>"

    html_content += """
            </ul>
        </div>
        <div class="section">
            <h2>7. Nikto Vulnerabilities Found</h2>
            <ul>
    """

    for finding in nikto_findings:
        html_content += f"<li>{finding}</li>"

    html_content += """
            </ul>
        </div>
        <div class="section">
            <h2>8. Nikto CVEs from NIST</h2>
            <ul>
    """

    for cve in nikto_cves:
        html_content += f"<li>{cve['id']}: {cve['description']}</li>"

    html_content += """
            </ul>
        </div>
    </body>
    </html>
    """

    try:
        config = pdfkit.configuration(wkhtmltopdf="C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
        pdfkit.from_string(html_content, "WebServer_Security_Report.pdf", configuration=config)
        logging.info("[+] Security Report saved as 'WebServer_Security_Report.pdf'.")
    except Exception as e:
        logging.error(f"[-] Error generating PDF: {e}")

# ** Main Function **
def main():
    # Run Scans
    nmap_results = run_nmap()
    if not nmap_results:
        logging.error("[-] Nmap scan failed. Exiting.")
        return

    nikto_results = run_nikto()
    if not nikto_results:
        logging.error("[-] Nikto scan failed. Exiting.")
        return

    # Extract data
    apache_version = extract_apache_version(nmap_results)
    open_ports = extract_open_ports(nmap_results)
    port_findings = analyze_open_ports(nmap_results)
    nikto_findings = extract_nikto_findings(nikto_results)

    # Fetch CVEs for Apache & Nikto vulnerabilities
    apache_cves = fetch_cves_from_nist([f"Apache {apache_version}"]) if apache_version else []
    filtered_nikto_queries = [NIKTO_VULN_MAPPING[key] for key in NIKTO_VULN_MAPPING if key in "\n".join(nikto_findings)]
    nikto_cves = [cve for query in filtered_nikto_queries for cve in fetch_cves_from_nist([query])]


    # Generate report
    generate_report(
        nmap_results,
        nikto_results,
        apache_version,
        open_ports,
        port_findings,
        apache_cves,
        nikto_findings,
        nikto_cves
    )

if __name__ == "__main__":
    main()