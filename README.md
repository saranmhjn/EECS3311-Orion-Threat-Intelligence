# Orion Threat Intelligence (CTI) & AI Agent Framework

Orion is a dual-mode Cyber Threat Intelligence (CTI) application and AI agent framework built in Java and JavaFX. Designed for proactive threat hunting, automated indicator extraction, and local SQLite caching, Orion provides both a polished graphical workspace and a terminal shell powered by the Groq LLM backend.

---

## 🚀 Key Features

* **Dual-Mode Architecture:**
  * **Graphical User Interface (GUI):** A modern, glassmorphism JavaFX workspace featuring real-time data filtering, single-row action grids, and rich HTML-rendered AI output.
  * **Command Line Interface (CLI):** An interactive terminal shell featuring ANSI color-coding, ASCII art branding, screen wiping, and truncated advisory tables.
* **Groq AI Integration:** Leverages high-performance Groq LLM endpoints to generate executive summaries, enterprise mitigation playbooks, environment-specific triage reports, and security gap analyses.
* **Feed Synchronization:** Ingests and caches threat feeds from the CISA Known Exploited Vulnerabilities (KEV) catalog and the NIST National Vulnerability Database (NVD).
* **Automated Log Correlation & IOC Extraction:** Scans local audit logs for threat signatures and extracts defanged indicators of compromise (IPs, hashes, domains) from unstructured text.
* **Portable One-Click Launchers:** Pre-configured Windows batch scripts designed for zero-friction evaluation and grading.

---

## 📋 System Requirements

* **Java Development Kit (JDK):** Version 21 or higher.
* **Apache Maven:** Version 3.8+ (for building and dependency management).
* **Groq API Key:** 
    Required for AI-powered summarization, triage, and mitigation features.
    Generate the free API key at - https://console.groq.com

---


## 🛠️ Installation & Setup

1. **Clone the Repository:**
```bash
git clone [https://github.com/saranmhjn/EECS3311-Orion-Threat-Intelligence.git](https://github.com/saranmhjn/EECS3311-Orion-Threat-Intelligence.git)
cd EECS3311-Orion-Threat-Intelligence
```

2. **Configure Environment Variables:**
Create a '.env' in the root directory and paste the following code snippet
```env
GROQ_API_KEY=*your_actual_groq_api_key_here*
```

3. **Example Files:**
Examples of environment configuration, report, ioc prompt, and log files are available in the `examples/` directory.

## 🎮 How to Run

1. **Method 1: One-Click Batch Launchers**
  Simply double-click the respective batch script located in the project root directory.
  ```text
  Launch GUI Workspace: Double-click run_gui.bat
  Launch CLI Terminal: Double-click run_cli.bat
  ```

2. **Method 2: Manual Terminal Execution via Maven**
```text
  Command to Launch GUI - mvn clean compile javafx:run
  Command to Launch CLI - mvn clean compile org.codehaus.mojo:exec-maven-plugin:3.1.0:java -Dexec.mainClass="ca.yorku.eecs3311.orion.boundary.OrionCLI"
  ```

## ⌨️ CLI Command Reference
| Command | Description |
| :--- | :--- |
| `list [limit]` | Display truncated threat advisories (default limit: 15) |
| `sync <cisa\|nist>` | Ingest latest CVE feeds from CISA KEV or NIST NVD |
| `summarize <CVE-ID>` | Generate an AI executive summary for a specific vulnerability |
| `mitigate <CVE-ID>` | Generate an enterprise mitigation playbook |
| `correlate <filepath>` | Scan a local audit log file for threat signatures |
| `iocs <text>` | Extract defanged IPs, hashes, and domains from unstructured text |
| `query <question>` | Ask Orion AI a natural language security question |
| `clear` | Reload console and wipe the screen buffer |
| `exit` | Terminate the CLI session safely |

## 💡 Example Usage

1. **In the CLI Terminal**
Once you launch `run_cli.bat` and your environment is configured, you can execute commands directly:
```bash
orion(cti)> sync cisa
[*] Synchronizing CISA KEV feed...
[+] CISA KEV sync complete.

orion(cti)> list 5
[+] Showing 20 of 1769 cached advisories
ID            | Severity | Vendor   | Product           | Threat Type
CVE-2024-1234 | CRITICAL | GitLab   | Community Edition | Zero-Day Exploitation

orion(cti)> summarize CVE-2026-97229
[*] Querying Orion AI for summary on CVE-2026-97229...
=== AI EXECUTIVE SUMMARY ===
### Executive Summary for CVE-2026-97229

**Attack Vector**
- An unauthenticated attacker submits a specially crafted regular expression in a GitLab CI/CD configuration, triggering an integer overflow or wraparound in the regex engine.

**Operational Impact**
- Exploitation results in arbitrary code execution on the GitLab server, enabling full system compromise.
- The flaw can be exploited remotely without credentials, posing a high risk to internet?exposed GitLab instances.

**Affected Systems**
- All GitLab Community Edition (CE) and Enterprise Edition (EE) deployments that include the vulnerable CI/CD processing component.
- Versions prior to the vendor?released patch (as detailed in the GitLab security advisory) are impacted, especially when publicly accessible.

orion(cti)>  query What is an APT?
[*] Orion AI processing query...

=== ORION AI RESPONSE ===
### General Inquiry
- **APT** stands for *Advanced Persistent Threat*, a sophisticated, long?term cyber?attack targeting specific organizations.
- Attackers use stealthy methods, often backed by nation?states, to remain undetected while exfiltrating data.
- They combine multiple tactics (malware, zero?day exploits, social engineering) and maintain footholds for months or years.

```

2. **In the GUI Application**
To launch the graphical workspace, double-click `run_gui.bat` or execute `mvn clean compile javafx:run`. Once the glassmorphism workspace loads, you can utilize the top action grids, data tables, and AI output panels for the following features:

| GUI Feature | Action / Workflow | Description |
| :--- | :--- | :--- |
| **🔄 Sync Feeds** | Click the **"Sync CISA / NIST"** buttons | Triggers live API ingestion to fetch and cache the latest CVE records into your local SQLite database. |
| **📋 Filter** | Use the **"Search bar"** or **"Filter by Severity dropdown"** | Real-time filtering of loaded threat advisories by keyword, vendor, or CVSS severity score. |
| **✨ Summarize** | Select a CVE row -> Click **"Summarize Selected"** | Queries the Groq LLM backend to generate a structured executive summary. |
| **🛡️ Generate Mitigation** | Select a CVE row -> Click **"Genertae Mitigate"** | Builds an enterprise-grade remediation playbook tailored for the selected vulnerability. |
| **🔍 Gap Analysis** | Select a CVE row -> Click **Gap Analysis** | Evaluates organizational security gaps and defensive posture against active threat vectors. |
| **⚡ Auto-Triage** | Select a CVE row -> Click **"Auto Triage"** | Automatically parses system state and active advisories to prioritize high-risk vulnerabilities. |
| **💬 AI Chat Query** | Type in the natural language query box | Ask custom security or threat intelligence questions directly to the Orion AI agent. |
| **📊 Export Briefing** | Select a CVE row -> Click **"Export Briefing"** | Generates and saves clean, structured intelligence briefings and markdown summaries locally in the file named *'report.md'* |
| **📦 Batch Export**| Select multiple rows (use CTRL or SHIFT keys) ->  Click **"Export Briefing"** | Generates and saves clean, structured intelligence briefings and markdown summaries for multiple CVEs locally in the file named *'report.md'* |
| **📁 Correlate Logs** | Click on **"Correlate Logs"** -> Upload a log file (.txt format preferred) | Scans local log files against threat signatures to detect matches or indicators of compromise, outputs any anomalies detected in the log file. |
| **🔎 Extract IOCs** | Paste raw unstructured text into chat query bubble | Uses regex and pattern matching to pull Indicators of Compromise (IOC), such as IP Addresses, hashes, and domains out of text blocks. |


## 🏛️ Project Architecture
Orion is structured using a clean, enterprise-grade separation of concerns across multiple modular layers:

```text
ca.yorku.eecs3311.orion/
├── api/            # External API integration & raw feed parsing (CISA KEV, NIST NVD)
├── boundary/       # User presentation layers (OrionGUI JavaFX workspace & OrionCLI shell)
├── command/        # Command pattern implementation for modular CLI/GUI operations
├── controller/     # Central application controller orchestrating workflows and agents
├── database/       # SQLite database connectivity, schema setup, and local persistence
├── llm/            # AI agent engine managing Groq client calls, prompts, and parsing
├── model/          # Core domain entities (ThreatAdvisory, indicators, data structures)
├── observer/       # Observer pattern implementation for real-time asynchronous eventing
├── repository/     # Data access layer for querying and caching threat records
├── tool/           # Specialized security tools (log correlation & IOC extraction utilities)
└── util/           # System-wide formatting, string manipulation, and helper utilities
```


## 🤖 AI & Human Collaborative Development
This project was built through a collaborative human-AI workflow. Below is the documentation of the AI tools utilized during the implementation and development lifecycle:

### 1. Google Gemini (Personal AI Collaborator)
* **Tool/Platform:** Google Gemini
* **LLM Model Name:** Gemini Pro
* **Development Tasks & Features:** 
  * Architectural design assistance for structuring modular Java packages.
  * Debugging code.
  * Crafting and refining the custom `.bat` launchers and SQLite integration scripts.
  * Writing documentation, the project `README.md`, and formatting instructions.
* **Token Cost & Money Cost:** 
  * **Token Cost:** Standard developer session tier (~150,000 contextual tokens processed across multi-turn refactoring).
  * **Monetary Cost:** $6.79/month (Google AI Pro).

### 2. Groq Cloud API (Runtime AI Engine)
* **Tool/Platform:** Groq Developer Console & API SDK
* **LLM Model Name:** Llama 3 - openai/gpt-oss-120b; 
* **Development Tasks & Features:** 
  * Integrated directly into the Orion backend (`ca.yorku.eecs3311.orion.llm`) to power real-time AI features: executive threat summaries, automated enterprise mitigation playbooks, environment-specific triage reports, and security gap analyses.
* **Token Cost & Money Cost:** 
  * **Token Cost:** Dependent on runtime API inference calls during testing and evaluation.
  * **Monetary Cost:** $0.00 (Utilized Groq's developer free tier quota).

## 🎥 Video Demonstration Walkthrough

You can watch the complete feature demonstration walkthrough of **Orion Threat Intelligence** on YouTube:

👉 **[Watch the Orion Demonstration on YouTube](https://youtu.be/P0hejUG7d7c?si=8rdHeIDW6OxKnapa)**

### Timestamps:
* **0:00** - Introduction & Workspace Launch
* **0:33** - Feature F01: External Threat Advisory Ingestion (CISA & NIST)
* **1:07** - Feature F02: Automated Threat Bulletin Summarization
* **1:27** - Feature F03: Natural Language Threat Landscape Querying
* **2:01** - Feature F04: Insider Risk Log Correlation
* **2:49** - Feature F05: Automated Mitigation Strategy Generation & Execution
* **3:28** - Feature F06: Structured Indicator of Compromise (IoC) Extraction
* **4:18** - Feature F07: Executive Threat Intelligence Report Export
* **4:50** - Feature F08: Historical Threat Repository Search
* **5:22** - Feature F09: Dynamic Advisory Triage & Priority Scoring
* **5:58** - Feature F10: Security Control Gap Analysis
* **6:24** - New Feature 1: Multi-Select Batch Export
* **6:58** - New Feature 2: Live Threat News Carousel Footer
* **7:28** - CLI Terminal Demonstration (Dual-Mode Architecture)
