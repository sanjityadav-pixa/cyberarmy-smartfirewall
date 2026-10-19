# AEGIS // Smart Layer-7 Defense WAF

Autonomous Behavioral Threat Scoring, Active Honeypot Grid, and Real-Time WebSocket SOC Telemetry Console.

---

## 🚀 Quick Setup & Installation

Follow these steps to run the complete defense system locally.

### 1. Clone the Repository
```bash
git clone [https://github.com/](https://github.com/)<your-username>/smart-firewall.git
cd smart-firewall

#Install Dependencies
pip install -r requirements.txt


⚡ #Running the Servers
#   Run both services in separate terminals:

#Terminal 1: Core Backend Upstream Service
Runs backend_server.py 

Terminal 2: AEGIS L7 Reverse Proxy & Firewall Engine
Runs firewall_engine.py


# Access SOC Dashboard
Open your browser and navigate to:

Plaintext
http://localhost:8080/dashboard



#Testing & Verification Commands
#Test telemetry and mitigation rules using curl or by opening the URLs in your browser:

1. Normal Clean Traffic (Allowed - Green)
Bash
curl http://localhost:8080/api/balance

2. SQL Injection Attack (Blocked - Red)
Bash
curl "http://localhost:8080/api/user?name=' OR 1=1 --"

3. Cross-Site Scripting / XSS (Blocked - Red)
Bash
curl "http://localhost:8080/api/user?name=%3Cimg%20src=x%20onerror=alert(1)%3E"

4. Active Honeypot Trap (Instant Quarantine & 100 Risk Score)
Bash
curl http://localhost:8080/admin

---

### Step 3: File Save Karke GitHub Par Push Karein

File ko **`Ctrl + S`** se save karein, fir VS Code ke terminal me bas ye 3 commands chala dein:

```cmd
git add README.md
git commit -m "docs: add setup and execution instructions in README"
git push