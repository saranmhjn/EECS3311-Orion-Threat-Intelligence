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
git clone [https://github.com/your-username/orion-threat-intelligence.git](https://github.com/your-username/orion-threat-intelligence.git)
cd orion-threat-intelligence
```

2. **Configure Environment Variables:**
Create a '.env' in the root directory and paste the following code snippet
```env
GROQ_API_KEY=*your_actual_groq_api_key_here*
```

## 🎮 How to Run

1. **Method 1: One-Click Batch Launchers**
    Simply double-click the respective batch script located in the project root directory. These scripts automatically handle project cleaning, compilation, and dependency resolution:
    Launch GUI Workspace: Double-click *run_gui.bat*
    Launch CLI Terminal: Double-click *run_cli.bat*

2. **Method 2: Manual Terminal Execution via Maven**
    To Launch GUI, Run Command -  *mvn clean compile javafx:run*
    To Launch CLI, Run Command -  *mvn clean compile org.codehaus.mojo:exec-maven-plugin:3.1.0:java -Dexec.mainClass="ca.yorku.eecs3311.orion.boundary.OrionCLI"*

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