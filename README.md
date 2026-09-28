\# Sentinel



\*\*Defensive Cybersecurity Monitoring \& Threat Detection Platform\*\*



Sentinel is a Python-based defensive cybersecurity platform designed to ingest security logs, detect suspicious activity, enrich alerts with threat intelligence, calculate risk, correlate related alerts into incidents, and support incident investigation through a SOC-style dashboard.



The project focuses on detection engineering, explainable risk scoring, threat intelligence enrichment, incident correlation, persistence, automated testing, and continuous monitoring.



\---



\## Architecture



```text

Security Logs

&#x20;     │

&#x20;     ▼

┌───────────────┐

│   Ingestion   │

│ Reader/Parser │

└───────┬───────┘

&#x20;       │

&#x20;       ▼

┌────────────────────┐

│  Detection Engine  │

│                    │

│ SSH Brute Force    │

│ Port Scan          │

│ Suspicious Login   │

└─────────┬──────────┘

&#x20;         │

&#x20;         ▼

&#x20;      Alerts

&#x20;         │

&#x20;   ┌─────┴─────┐

&#x20;   ▼           ▼

Threat Intel  Risk Scoring

&#x20;   │           │

&#x20;   └─────┬─────┘

&#x20;         ▼

┌────────────────────┐

│ Incident           │

│ Correlation        │

└─────────┬──────────┘

&#x20;         │

&#x20;   ┌─────┴─────┐

&#x20;   ▼           ▼

&#x20;SQLite      SOC Dashboard

&#x20;               │

&#x20;               ▼

&#x20;         Investigation

