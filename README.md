# 🔥 **WP Hunter – WordPress Vulnerability Scanner**

**WP Hunter** is a powerful and comprehensive security scanner designed to detect vulnerabilities, misconfigurations, and sensitive information leaks in WordPress sites. With advanced detection capabilities and flexible command-line options, it is perfect for **CTF challenges, bug bounty hunting, and web security assessments**.

---

## 🚀 **Features**

### 🔍 **Target Discovery**
- Scans for backup files, debug logs, and sensitive configurations (`.git`, `.env`, etc.).  
- Identifies hidden and potentially exploitable WordPress paths.  

### ⚙️ **Plugin & Theme Detection**
- Enumerates installed plugins and themes.  
- Checks for **common vulnerabilities** and outdated versions.  

### 🔥 **Security Testing**
- Tests **XML-RPC** and **WP REST API** for potential exploits.  
- Examines forms and entry points for **XSS, CSRF**, and other attacks.  
- Scans for sensitive information patterns in responses.  

### 🛡️ **Stealth & Efficiency**
- **Random User-Agent rotation** to avoid detection.  
- Supports **proxy and cookie-based authenticated scanning**.  
- Configurable delays to prevent site overload.  

### 📊 **Advanced Reporting**
- Generates detailed reports with identified vulnerabilities.  
- Lists discovered forms and potential attack points.  
- Provides next-step recommendations for further exploitation.  

### ⚡ **Command-line Power**
- Supports **custom wordlists** for flexible scanning.  
- Includes **aggressive mode** for deeper inspection.  
- Multiple command-line options for customization.  

---

## ⚙️ **Installation**

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/wp-hunter.git
cd wp-hunter
