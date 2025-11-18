# **Decoy-Based Intrusion Monitoring System Using Honeypot Architecture**

A lightweight and security system that uses **decoy endpoints (honeypots)** to detect, analyze, and log unauthorized access attempts in real time. This project simulates a protected infrastructure by exposing realistic fake endpoints and monitoring attacker behavior without risking real assets.

## **Overview**

This system deploys a Node.js-based backend that:

* Exposes **decoy authentication endpoints** to attract malicious actors
* Monitors and logs suspicious activity (IP, user agents, payloads)
* Implements a **rate-limiter** to mimic firewalls
* Sends **real-time alerts** for critical intrusion attempts
* Provides structured logs for further threat analysis

It helps cybersecurity teams safely study attacker behavior while strengthening internal defenses.

---

## **Key Features**

* **Honeypot Authentication Module**
  Mimics a real login API and records brute-force or credential-stuffing attempts.

* **Behavioral Logging Engine**
  Captures IP, headers, payload patterns, and timestamps for every attempt.

* **Alert System (Email-based)**
  Sends alerts to administrators when thresholds or malicious patterns are detected.

* **Firewall-Style Rate Limiting**
  Throttles repeated requests and blocks automated attacks.

* **Modular Architecture**
  Clean separation of routes, utilities, and database logic.

---

## **Tech Stack**

| Layer      | Technology                     |
| ---------- | ------------------------------ |
| Backend    | Node.js, Express               |
| Database   | MongoDB (or your DB of choice) |
| Security   | Rate Limiting, Honeypot Traps  |
| Utilities  | Nodemailer, bcrypt             |
| Deployment | Any Node-compatible server     |

---
