# 🛡️ SSH Guardian

> A modern, dark-themed desktop application that analyzes Linux SSH authentication logs, detects brute-force attacks, and produces SOC-style incident reports.

Built with **Python 3** + **PyQt5**. Designed as a portfolio-grade project for cybersecurity / digital-forensics students and junior SOC analysts.

---

## ✨ Features

- 📂 **One-click import** of any `/var/log/auth.log` file (or custom log)
- 🔍 **Regex-based parser** extracts: timestamp, username, source IP, port, success/failure
- 🚨 **Brute-force detection** with configurable threshold (default ≥ 5 failed attempts)
- 🌐 **Attacker IP dashboard** ranked by activity, risk level, and breach indicator
- 🎯 **Most-targeted usernames** view (e.g. `root`, `admin`, `oracle`)
- ⚠️ **Possible-breach alarm** when a successful login follows a brute-force burst from the same IP
- 📄 **Incident report generator** — NIST SP 800-61 inspired `incident_report.txt`
- 🎨 **Modern dark cyber UI** (sidebar nav, KPI cards, color-coded risk levels)

---

## 🖼️ Screenshots

> Add your screenshots inside the `assets/` folder and reference them here.

```
assets/screenshot_dashboard.png
assets/screenshot_attackers.png
assets/screenshot_report.png
```

---

## 🧠 Cybersecurity Background

| Concept | Meaning |
|---|---|
| **SSH** | Secure Shell — remote admin protocol on TCP/22. |
| **Brute force** | Mass automated password guessing. |
| **auth.log** | Linux file logging every authentication attempt. |
| **IoC** | Indicator of Compromise — e.g. attacker IP, targeted username. |
| **SIEM** | Security Information & Event Management (Splunk, Wazuh, ELK). |
| **Incident report** | Structured document used by SOC to communicate findings. |

SSH Guardian acts as a **mini-SIEM**: it normalizes raw logs, correlates events by IP, classifies risk, and produces an actionable report — mirroring real-world SOC workflows.

---

## ⚙️ Installation

### Prerequisites
- Python ≥ 3.10
- pip
- A desktop environment (Windows / macOS / any Linux DE)

### Steps
```bash
# 1) Clone
git clone https://github.com/<your-username>/SSH-Guardian.git
cd SSH-Guardian

# 2) (Recommended) virtualenv
python -m venv venv
source venv/bin/activate     # Linux/macOS
# .\venv\Scripts\activate    # Windows

# 3) Install dependencies
pip install -r requirements.txt

# 4) Run
python main.py
```

---

## 🚀 Usage

1. Launch the app: `python main.py`
2. Click **📂 Import auth.log** and select a file (try `logs/sample_auth.log`).
3. Inspect the **Dashboard** for KPIs, top attacker, and most-targeted users.
4. Switch to **Attackers** tab for the full IP intelligence table.
5. Switch to **Raw Logs** tab to view the original log content.
6. Adjust **brute-force threshold** (default 5) in the header spinbox.
7. Click **📄 Generate Report** → see `reports/incident_report.txt`.

---

## 📁 Folder Structure

```
SSH-Guardian/
│
├── main.py                       # Entry point (QApplication)
├── requirements.txt
├── README.md
├── assets/                       # screenshots, icons
├── reports/                      # generated incident reports
├── logs/
│   └── sample_auth.log           # example log for testing
│
├── gui/                          # PyQt5 layer
│   ├── dashboard.py              # main window
│   ├── styles.py                 # dark theme QSS
│   └── widgets.py                # custom widgets (StatCard)
│
├── analyzer/                     # business logic
│   ├── parser.py                 # auth.log → structured events
│   ├── detector.py               # brute-force detection
│   └── report_generator.py       # incident report writer
│
└── utils/                        # helpers & constants
    ├── helpers.py
    └── constants.py
```

---

## 🛠️ Technologies

- **Language**: Python 3
- **GUI**: PyQt5
- **Standard libs**: `re`, `collections`, `datetime`, `dataclasses`, `os`, `sys`
- **(Optional)** `pandas`, `matplotlib` for future analytics extensions

---

## 🧪 Testing the core (without GUI)

```bash
python -c "
from analyzer.parser import LogParser
from analyzer.detector import BruteForceDetector
from analyzer.report_generator import ReportGenerator

events  = list(LogParser().parse_file('logs/sample_auth.log'))
result  = BruteForceDetector().analyze(events)
ReportGenerator().generate(result, source_file='logs/sample_auth.log')
print('Top attacker:', result.top_attacker.ip)
"
```

---

## 🔮 Future Improvements

- ⏱️ **Real-time tailing** (`watchdog` / `tail -f` thread) for live auth.log monitoring
- 🌍 **GeoIP enrichment** (MaxMind GeoLite2) — map attackers by country
- 🧠 **ML anomaly detection** for slow-burn brute force
- 📊 **Matplotlib charts** embedded with `FigureCanvasQTAgg`
- 🗃️ **SQLite persistence** for multi-file historical analytics
- 🤝 **SIEM export** (Syslog / CEF / JSON-Lines)
- 📦 **PyInstaller** single-file binary release
- 🛡️ **Auto-block** integration with `iptables` / `firewalld`

---

## 👨‍💻 Author

Digital Forensics Engineering Student — Cybersecurity Portfolio.

If this project helped you, ⭐ star the repo and share it!

---

## 📜 License

MIT — free for educational and commercial use.
