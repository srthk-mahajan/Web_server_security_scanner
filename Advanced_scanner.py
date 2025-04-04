import subprocess
import re
import requests
import pdfkit
import logging
import time
import google.generativeai as genai

GENAI_API_KEY = "AIzaSyD_Bqnkjqv77P-QFzPOU7MqKzchSTCgjOM"
genai.configure(api_key=GENAI_API_KEY)
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
    nikto_config = "C:\\Nikto\\program\\nikto.conf.default"  # Adjust path if necessary
    cmd = [
        "perl", "nikto.pl", "-h", TARGET_URL, 
         nikto_config
    ]

    try:
        # Run Nikto and capture all output at once
        result = subprocess.run(cmd, capture_output=True, text=True, cwd="C:\\Nikto\\program", timeout=300)

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
        cves = [{"id": item["cve"]["id"], "description": item["cve"].get("descriptions", [{}])[0].get("value", "No description available")}
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

def analyze_findings(nmap_output, nikto_output, nikto_cves):
    """Analyzes security findings and suggests best remediation steps using Gemini AI."""

    prompt = f"""
    You are a cybersecurity expert. Based on the following scan results, Create a detailed comprehensive results

    **1️⃣ Nmap Findings (Highest Priority)**
    {nmap_output}

    **2️⃣ Nikto Findings (High Priority - Web Security)**
    {nikto_output}

    **3️⃣ NIST CVEs (Lower Priority - Additional Context)**
    {nikto_cves}

    🎯 **Remediation Guidelines:**
    - Prioritize **network security issues** (firewall rules, service hardening).
    - Provide **web security hardening steps** (Apache/Nginx fixes, headers, SSL).
    - Suggest **patches or config changes** to mitigate risks.
    - If a vulnerability has no patch, suggest **mitigation strategies**.

    🔍 **Format the response as follows:**
    - **Critical Remediations (High Priority)**
    - **Recommended Fixes (Medium Priority)**
    - **Additional Hardening Steps (Best Practices)**

    Provide responses in **bullet points** with clear, technical steps.
    """

    try:
        model = genai.GenerativeModel("gemini-2.0-flash")
        response = model.generate_content(prompt)
        
        return response.text
    except Exception as e:
        return f"Error fetching AI response: {e}"
# ** Generate Security Report (PDF) **

def generate_report(ai_results):
    """
    Generates a PDF report using AI-processed security findings.
    
    Args:
        ai_analysis (str): AI-generated security analysis, including risk assessment and remediation steps.
    
    Output:
        Saves a PDF report named 'WebServer_Security_Report.pdf'.
    """
    # Define the HTML content with AI analysis
    html_content = f"""
    <html>
    <head>
        <title>Web Server Security Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
            h1, h2 {{ color: #333; }}
            h1 {{ text-align: center; }}
            .section {{ margin-bottom: 20px; padding: 15px; border-bottom: 2px solid #ddd; }}
            .critical {{ color: red; font-weight: bold; }}
            .medium {{ color: orange; font-weight: bold; }}
            .low {{ color: green; font-weight: bold; }}
            pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <h1>🔍 Web Server Security Assessment Report</h1>
        <hr>

        <div class="section">
            <h2>📌 AI-Powered Security Analysis</h2>
            <pre>{ai_results}</pre>
        </div>

        <p><i>Generated automatically using AI-based vulnerability assessment.</i></p>
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

    # Extract Nikto findings
    nikto_findings = extract_nikto_findings(nikto_results)

    # Map Nikto findings to vulnerability queries
    filtered_nikto_queries = [
        NIKTO_VULN_MAPPING[key] for key in NIKTO_VULN_MAPPING
        if key in "\n".join(nikto_findings)
    ]

    # Fetch CVEs for Nikto vulnerabilities
    nikto_cves = []
    for query in filtered_nikto_queries:
        cves = fetch_cves_from_nist([query])
        nikto_cves.extend(cves)

    # Analyze findings using AI
    ai_results = analyze_findings(nmap_results, nikto_results, nikto_cves)
    if not ai_results:
        logging.error("[-] AI analysis failed. Exiting.")
        return

    # Generate report
    generate_report(ai_results)

if __name__ == "__main__":
    main()