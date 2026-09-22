# 🛡️ IoT Shield — Cyber Risk Analyzer

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.0-green.svg)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/Database-SQLite%20%2F%20SQLAlchemy-orange.svg)](https://www.sqlite.org/)
[![UI](https://img.shields.io/badge/UI-Glassmorphism%20SPA-purple.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](#)

> **IoT Shield** is a feature-rich, full-stack cybersecurity diagnostic web application designed to audit Internet of Things (IoT) devices, assess network vulnerability vectors, calculate real-time security index scores (0–100), and deliver prioritized remediation roadmaps.

---

## 💡 What does this project do? (Simple Explanation)

Imagine a smart home or office filled with connected devices (Security Cameras, Wi-Fi Routers, Smart Locks, Smart TVs). Unpatched firmware, weak default passwords (`admin`/`admin`), and open ports (e.g., RTSP port 554, UPnP port 1900) make these devices easy targets for automated botnets and hackers.

**IoT Shield** solves this problem by giving users a security auditing dashboard:
1. You select/input a device and its configuration (connection type, default credentials, exposed ports).
2. The custom **Risk Engine** calculates a **Security Risk Index Score (0 to 100)**.
3. The app classifies the risk level (**Low**, **Medium**, or **High**), flags specific vulnerability threats, and provides step-by-step **remediation instructions**.
4. All scans are saved in an **SQLite Database** and visualized on an interactive **Analytics Dashboard**.

---

## 📂 File-by-File Breakdown (How the Project Code Works)

```text
iot-risk-analyzer/
├── app.py               # 1. MAIN FLASK SERVER & REST API CONTROLLERS
├── models.py            # 2. DATABASE MODELS (SQLAlchemy ORM)
├── risk_engine.py       # 3. SCORING ALGORITHM & THREAT ENGINE
├── requirements.txt     # 4. PYTHON DEPENDENCIES MANIFEST
├── README.md               # 5. DOCUMENTATION MANUAL (This file)
├── static/
│   ├── css/style.css    # 6. GLASSMORPHISM DARK-MODE STYLESHEET
│   └── js/app.js        # 7. FRONTEND LOGIC & CHART.JS INTERACTIVITY
└── templates/
    └── index.html       # 8. DASHBOARD SINGLE-PAGE APPLICATION (SPA)
```

### Detailed Role of Each File:

1. **[`app.py`](file:///d:/iot-risk-analyzer/app.py) (The Server & REST Controller)**:
   - Starts the Python Flask web server listening on port `5000`.
   - Defines HTTP routes to serve the frontend web page (`/`) and handle REST APIs (`/api/analyze`, `/api/scans`, `/api/dashboard-stats`, `/api/threat-intelligence`).

2. **[`models.py`](file:///d:/iot-risk-analyzer/models.py) (The Database Structure)**:
   - Uses **Flask-SQLAlchemy** ORM to manage the SQLite database (`iot_risk.db`).
   - `ScanHistory`: Table storing every device scan (name, manufacturer, connection type, risk score, threats found, timestamp).
   - `ThreatTemplate`: Table storing pre-defined cyber threat intelligence signatures (e.g., Default Admin Credentials, RTSP Stream Exposure).

3. **[`risk_engine.py`](file:///d:/iot-risk-analyzer/risk_engine.py) (The Scoring Logic Engine)**:
   - Evaluates input security parameters and computes a score from 0 to 100:
     - Default credentials unchanged? $\rightarrow$ **+25 Risk Points**
     - Subnet not isolated? $\rightarrow$ **+15 Risk Points**
     - High-risk ports open (e.g., 554 RTSP, 80 HTTP, 1900 UPnP)? $\rightarrow$ **+25 Risk Points**
     - Outdated firmware? $\rightarrow$ **+15 Risk Points**
   - Categorizes score into **Low (0–35)**, **Medium (36–65)**, or **High (66–100)**.

4. **[`templates/index.html`](file:///d:/iot-risk-analyzer/templates/index.html) (The Page Skeleton)**:
   - Single-Page Application (SPA) HTML template containing three main views:
     - **Operations Center (Dashboard)**
     - **Device Scanner Audit**
     - **Threat Intelligence Library**

5. **[`static/css/style.css`](file:///d:/iot-risk-analyzer/static/css/style.css) (The Styling)**:
   - Modern dark-mode **Glassmorphism** styling with CSS custom variables, translucent card containers, glowing status badges, and responsive layouts.

6. **[`static/js/app.js`](file:///d:/iot-risk-analyzer/static/js/app.js) (The Frontend Interactivity)**:
   - Uses JavaScript `fetch()` API for seamless asynchronous HTTP requests to Flask REST endpoints without page reloads.
   - Renders dynamic data visualization graphics powered by **Chart.js**.

---

## 🏗️ Technical Architecture

```text
               ┌─────────────────────────────────────────────────┐
               │           Glassmorphism SPA Frontend            │
               │   HTML5 | Vanilla CSS3 | JavaScript (ES6+)      │
               │               Chart.js Analytics                │
               └──────────────────────┬──────────────────────────┘
                                      │ HTTP / REST API
                                      ▼
               ┌─────────────────────────────────────────────────┐
               │                 Flask Backend                   │
               │                    (app.py)                     │
               └──────────────┬───────────────────┬──────────────┘
                              │                   │
                              ▼                   ▼
               ┌───────────────────────┐ ┌───────────────────────┐
               │    SQLAlchemy ORM     │ │   Cyber Risk Engine   │
               │     (models.py)       │ │   (risk_engine.py)    │
               └───────────┬───────────┘ └───────────────────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │    SQLite Database    │
               │     (iot_risk.db)     │
               └───────────────────────┘
```

---

## 🚀 Step-by-Step Setup & Run Guide (Beginner Friendly)

### Prerequisites
- **Python 3.8 or higher** installed on your computer. Verify by running in your terminal:
  ```bash
  python --version
  ```

---

### Step 1: Open Terminal in Project Folder
In VS Code, press `Ctrl + ~` to open the integrated terminal (or go to **Terminal > New Terminal**).
Ensure you are in the project folder:
```powershell
cd d:\iot-risk-analyzer
```

---

### Step 2: Set Up Virtual Environment (Recommended)
Isolate project dependencies:

- **Windows (PowerShell)**:
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```

- **macOS / Linux**:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

---

### Step 3: Install Required Packages
Install Flask and Flask-SQLAlchemy from `requirements.txt`:
```powershell
pip install -r requirements.txt
```

---

### Step 4: Launch the Server
Start the local server instance:
```powershell
python app.py
```
*Output will indicate the server is live:*
```text
 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5000
```

---

### Step 5: Open Web Dashboard
Open your browser and navigate to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 📡 REST API Reference

| Endpoint | HTTP Method | Description |
| :--- | :--- | :--- |
| `/` | `GET` | Serves the main Single-Page Application (SPA) HTML dashboard |
| `/api/analyze` | `POST` | Processes device inputs, computes risk score, saves to DB, returns analysis |
| `/api/scans` | `GET` | Fetches all historical device scans ordered by timestamp |
| `/api/scans/<id>` | `DELETE` | Deletes a specific device scan record by ID |
| `/api/dashboard-stats` | `GET` | Returns aggregated metrics (total scans, average score, risk breakdown) |
| `/api/threat-intelligence` | `GET` | Retrieves all threat signatures from the Threat Library |
| `/api/download-zip` | `GET` | Generates and downloads an archived `.zip` copy of the project |

---

## 📝 License

This project is open-source and available under the **MIT License**.

