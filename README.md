# Web_server_security_scanner
This script automates security assessments of web servers by leveraging tools like Nmap , Nikto , and the NIST National Vulnerability Database (NVD) . It scans for open ports, detects vulnerabilities, fetches associated CVEs, and generates a comprehensive PDF report.

Table of Contents
Features
Prerequisites
Installation
Usage
Report Generation
Troubleshooting
Contributing
License
Features
Nmap Integration : Scans for open ports and identifies services running on the target server.
Nikto Integration : Detects web server vulnerabilities, misconfigurations, and outdated software.
NIST API Lookup : Fetches CVEs for detected Apache versions and Nikto vulnerabilities.
Automated Report Generation : Generates a detailed PDF report summarizing findings.
Optimized Performance : Includes configurable timeouts and parallel execution for faster scans.
Prerequisites
Before running the script, ensure the following tools and libraries are installed:

Tools
Python 3.x : The script is written in Python 3. Install it from python.org .
Nmap : A network scanning tool. Download it from nmap.org .
Nikto : A web server vulnerability scanner. Download it from Nikto's GitHub repository .
wkhtmltopdf : Required for generating PDF reports. Download it from wkhtmltopdf.org .
Libraries
Install the required Python libraries using pip:
pip install requests pdfkit
Installation
git clone https://github.com/your-username/web-server-security-tool.git
cd web-server-security-tool
Install dependencies:
pip install -r requirements.txt
Configure Paths:
Update the paths for nikto.pl and nikto.conf.default and subfolders-docs,plugin,template and database in the script if they differ from the default locations.
Run the script as follows:
python security_assessment.py
Customization
You can customize the script by modifying the following constants at the top of the file:

TARGET_IP: The IP address of the target server.
TARGET_URL: The URL of the target server (e.g., http://localhost)
TARGET_IP = "192.168.1.10"
TARGET_URL = "http://192.168.1.10"
Report Generation
The script generates a detailed PDF report named WebServer_Security_Report.pdf. The report includes:

Nmap scan results.
Nikto scan results.
Detected Apache version and associated CVEs.
Open ports and risky ports.
Nikto vulnerabilities and associated CVEs.
The report is saved in the same directory as the script.
Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements:

Fork the repository.
Create a new branch (git checkout -b feature/YourFeatureName).
Commit your changes (git commit -m "Add YourFeatureName") .
Push to the branch (git push origin feature/YourFeatureName).
Open a pull request.
