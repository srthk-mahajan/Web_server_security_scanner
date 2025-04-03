# **Web Server Security Scanner**  

This script automates security assessments of web servers using **Nmap** and **Nikto**. It cross-references the findings with the **NIST National Vulnerability Database (NVD)** to detect vulnerabilities. The tool scans for open ports, fetches associated CVEs, and generates a **detailed PDF report**.  

---

## **Table of Contents**  

- [Features](#features)  
- [Prerequisites](#prerequisites)  
  - [Tools](#tools)  
  - [Libraries](#libraries)  
- [Installation](#installation)  
- [Customization](#customization)  
- [Report Generation](#report-generation)  
- [Contributing](#contributing)  

---

## **Features**  

- **🔍 Nmap Integration** – Scans for open ports and identifies running services.  
- **🛡️ Nikto Integration** – Detects web server vulnerabilities and misconfigurations.  
- **⚡ NIST API Lookup** – Fetches CVEs for **Apache versions** and **Nikto vulnerabilities**.  
- **📄 Automated Report Generation** – Creates a **detailed PDF report** of findings.  
- **🚀 Optimized Performance** – Configurable timeouts and parallel execution for faster scans.  

---

## **Prerequisites**  

Before running the script, ensure the following tools and libraries are installed:  

### **Tools**  

- **Python 3.x** – Install from [python.org](https://www.python.org/)  
- **Nmap** – Download from [nmap.org](https://nmap.org/)  
- **Nikto** – Download from [Nikto's GitHub](https://github.com/sullo/nikto)  
- **wkhtmltopdf** – Required for PDF generation ([Download](https://wkhtmltopdf.org/))  

### **Libraries**  

Install the required Python libraries:  

```sh
pip install requests pdfkit
```

---
**Since pip installations often fail on Kali, it's recommended to use a virtual environment:**
```sh
python3 -m venv scanner_env
source scanner_env/bin/activate
pip install requests pdfkit

```
## **Installation**  

1. Clone the repository:  

   ```sh
   git clone https://github.com/your-username/web-server-security-tool.git
   cd web-server-security-tool
   ```

2. Install dependencies:  

   ```sh
   pip install -r requirements.txt
   ```

3. Configure paths:  

   Update the paths for **nikto.pl**, **nikto.conf.default**, and the subfolders (**docs, plugin, template, database**) in the script if they differ from the default locations(all of them should be at C:\Nikto)  

4. Run the script:  

   ```sh
   python security_assessment.py
   ```

---

## **Customization**  

Modify the following constants in the script to set the target server:  

```python
TARGET_IP = "192.168.1.10"
TARGET_URL = "http://192.168.1.10"
```

---

## **Report Generation**  

The script generates a **detailed PDF report** named **`WebServer_Security_Report.pdf`**. It includes:  

- **Nmap scan results**  
- **Nikto scan results**  
- **Detected Apache version and associated CVEs**  
- **Open ports and risky ports**  
- **Nikto vulnerabilities and associated CVEs**  

📂 **The report is saved in the same directory as the script.**  

---

## **Contributing**  

Contributions are welcome! To contribute:  

1. **Fork** the repository.  
2. Create a **new branch**:  

   ```sh
   git checkout -b feature/YourFeatureName
   ```

3. Commit your changes:  

   ```sh
   git commit -m "Add YourFeatureName"
   ```

4. Push to your branch:  

   ```sh
   git push origin feature/YourFeatureName
   ```

5. Open a **pull request**.  

---

