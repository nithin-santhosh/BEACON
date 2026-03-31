# BEACON  
### Behavioural Backdoor Analysis Tool for Windows
![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange)
![Detection](https://img.shields.io/badge/Detection-Heuristic-green)
---

##  Introduction

BEACON is a host-based behavioural analysis framework designed to detect stealthy backdoors and suspicious activities in Windows systems.

Unlike traditional signature-based tools, BEACON focuses on **runtime behaviour**, identifying threats through:
- Process activity  
- Persistence mechanisms  
- Network anomalies  
---

##  System Architecture

BEACON follows a modular design consisting of the following components:

### 1. Monitoring Layer
- Process monitoring  
- Network activity tracking  
- Persistence detection (startup, registry)

### 2. Feature Extraction
- Converts raw system activity into structured behavioural features  

### 3. Detection Engine
- Heuristic-based classification  
- Risk scoring mechanism  
- Threat categorization  

### 4. Forensics Module
- File hash generation (MD5, SHA-256)  
- Case indexing and tracking  
- Evidence collection  

### 5. Reporting Engine
- Automated PDF report generation  
- Structured incident summaries  

### 6. User Interface
- Tkinter-based GUI dashboard  
- Displays alerts, risk levels, and analysis results  

---

##  Features

- Real-time process monitoring  
- Detection of persistence mechanisms  
- Network anomaly identification  
- Risk-based threat classification  
- Behavioural (heuristic) detection approach  
- Forensic evidence generation  
- Automated report creation  
- Lightweight GUI interface  

---

##  Detection Approach

BEACON uses a **heuristic-based detection model** instead of machine learning.

### Why not ML?
- Lack of reliable labeled datasets for backdoor behaviour  
- Avoidance of unreliable predictions from insufficient data  

### Detection Logic
- Suspicious process patterns  
- Unauthorized persistence activity  
- Abnormal network connections  

Each event is evaluated using a **risk scoring system**, leading to:
- Low Risk  
- Medium Risk  
- High Risk  

---

##  Tech Stack

- Python  
- Tkinter (GUI)  
- psutil (system monitoring)  
- pandas & matplotlib (data handling)  
- scikit-learn (experimental, not used in pipeline)  
- reportlab (PDF reports)  

---

##  How to Run

```
pip install -r requirements.txt
python -m ui.beacon_gui
```
---

##  Project Structure
```
BEACON/
├── analysis/
├── detection/
├── features/
├── forensics/
├── monitor/
├── report/
├── sandbox/
├── ui/
├── requirements.txt
└── README.md
```
---

