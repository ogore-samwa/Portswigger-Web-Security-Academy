# Vulnerability Deep-Dive: Blind SQL Injection (Blind SQLi)

## Overview
**Blind SQL Injection** occurs when an application is vulnerable to an injection attack, but its HTTP responses do not mirror the results of the underlying SQL query or expose descriptive database error messages. 

Because standard techniques like `UNION` attacks are ineffective when data isn't directly reflected, an attacker must infer data by asking the database a systematic sequence of **True or False (Boolean) questions** and analyzing how the application's behavior shifts.

---

## Core Mechanics: Triggering Conditional Responses

Consider a web application that extracts analytics data from a cookie parameter to verify user sessions:

```http
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
```

Behind the scenes, the web server executes a dynamic query tracking active traffic records:
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```

If the application behaves differently depending on whether the query returns data, we can inject logic statements to observe the behavioral threshold.

### The Boolean State Test:
* **The True State:** Appending a valid condition (`' AND '1'='1`) keeps the underlying query true. The application executes normally and displays a conditional component, such as a **"Welcome back"** message.
  ```sql
  SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'xyz' AND '1'='1'
  ```
* **The False State:** Appending an invalid condition (`' AND '1'='2`) forces the query to return no data rows. The application suppresses the conditional component, and the **"Welcome back"** message disappears.
  ```sql
  SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'xyz' AND '1'='2'
  ```

---

## Data Extraction Methodology (Step-by-Step)

Once boolean control over the UI is confirmed, an attacker can extract sensitive database parameters piece by piece.

### Step 1: Mapping Schema Infrastructure
Verify that the data tables and target administrative rows exist before launching extraction queries.
```sql
-- Confirming table structure existence
' AND (SELECT 'a' FROM users LIMIT 1)='a

-- Confirming administrative user record existence
' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```

### Step 2: Isolating Password Length
Determine the target string boundary size by testing progressive numerical inequalities until the true response drops.
```sql
-- Testing if the string length is greater than 1 character
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a

-- Testing sequentially until the "Welcome back" tracker disappears
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>20)='a
```

### Step 3: Character-by-Character Enumeration
Because blind queries only yield a yes/no state, strings must be broken down into single character bytes using string slicing functions like `SUBSTRING()` or `SUBSTR()`.

```sql
-- Testing if the 1st character of the administrator password is 'a'
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'

-- Testing if the 2nd character of the administrator password is 'b'
' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='b'
```

---

## Automation & Scale (Burp Suite Intruder)

Manually brute-forcing strings character-by-character across large alpha-numeric character sets is highly inefficient. Automation tools like **Burp Suite Intruder** streamline this life cycle:

1. **Set Payload Positions:** Isolate the substring character index and the target matching value as separate attack points.
2. **Configure Match Filters:** Set up a strict **Grep - Match** rule targeting the conditional string pattern (e.g., `Welcome back`).
3. **Analyze Results:** Sort through the automated attack logs. The character parameters that trigger a successful verification match indicate the confirmed character value at that exact index position.

---

## Remediation Strategies

* **Immutable Parameterization:** Migrate all data aggregation frameworks over to strict **Prepared Statements**. Forcing input validation via parameterized bindings ensures that payload metadata elements (like single quotes or logic operators) are interpreted purely as static literals rather than executable database logic.
* **Input Allowlisting:** Restrict operational cookie formats using server-side regex validations, ensuring token headers match rigid alphanumeric constraints while blocking structural SQL keywords.
