# azure-vnet-port-scanner
A Python tool for scanning Azure NSGs for insecure ports and logging results.

# 🔍 Azure VNET Port Scanner (Python + Azure SDK)

This project is a Python-based tool designed to identify potentially insecure ports within Azure Network Security Groups (NSGs). The scanner checks for commonly exploited ports such as FTP, Telnet, POP3, SMB, HTTP, LDAP, and RDP, and logs the results to a text file for further analysis.

---

## ✅ Why This Project?

This project was developed to showcase network security scanning within Azure. By using the Azure SDK for Python, the scanner identifies common vulnerabilities in NSG configurations and provides a consolidated report of open or misconfigured ports. This tool can serve as a foundational security utility for cloud infrastructure.

---

## ✅ Features

* Scans for commonly insecure ports within Azure NSGs (21, 23, 110, 139, 445, 3389, 80)
* Logs scan results to a text file (`scan_results.txt`)
* Supports Azure authentication via Azure CLI and DefaultAzureCredential
* Modular design for extending port lists or logging formats

---

## 🛠️ Architecture Overview

```
[User Input]
↓
[Python Script]
↓
[Azure SDK - Network Management Client]
↓
[Network Security Groups]
↓
[Scan Results - Logged to scan_results.txt]
```

---

## 📦 Project Structure

```
azure-vnet-port-scanner/
├── README.md
├── LICENSE
├── .gitignore
├── port_scanner.py
└── requirements.txt
```

---

## 🚀 Deployment Steps

### ✅ 1. Clone This Repository

```bash
git clone https://github.com/yourusername/azure-vnet-port-scanner.git
cd azure-vnet-port-scanner
```

### ✅ 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### ✅ 3. Run the Scanner

```bash
python port_scanner.py
```

### ✅ 4. Enter Azure Details

* Subscription ID
* Resource Group Name
* NSG Name

### ✅ 5. View Scan Results

```bash
cat scan_results.txt
```

---

## ✅ Key Learnings and Takeaways

* Implemented Azure SDK for Python to query NSG rules
* Applied logging mechanisms to capture scan results in a structured format
* Practiced handling authentication via Azure CLI and DefaultAzureCredential

---

## ✅ Challenges and Solutions

* **Issue:** Failed authentication due to missing Azure CLI login.

  * **Solution:** Ensured Azure CLI authentication with `az login` before running the script.

* **Issue:** Timeout when querying large NSGs.

  * **Solution:** Implemented error handling and retry logic for Azure SDK requests.

---

## 👨‍💻 Author

Built by Gideon Bennett — showcasing skills in Python, Azure SDK, and cloud security analysis.
