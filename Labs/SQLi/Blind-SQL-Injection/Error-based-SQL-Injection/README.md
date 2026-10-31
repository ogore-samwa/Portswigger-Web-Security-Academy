# Advanced SQL Injection: Error-Based & Blind Vulnerabilities (Conditional Errors)

This module explores how to detect and exploit **Blind SQL Injection** by forcing the database to trigger conditional runtime errors. This technique allows an attacker to extract sensitive data even when the application does not visibly return database records or change its standard page content based on boolean logic.

---

## 1. Overview of Error-Based SQL Injection

**Error-based SQL injection** occurs when an attacker triggers a database error to infer or directly extract sensitive information. Even when an application is considered "blind" (i.e., it does not display raw query results), error handling mechanisms often reveal the internal state of the database.

Depending on the application's configuration and database type, error-based exploitation generally falls into two categories:

*   **Conditional Error Inducement:** Modifying a query so that a database error is thrown *only if* a specific boolean condition evaluates to true. The resulting change in the HTTP response (e.g., a `500 Internal Server Error` vs. a `200 OK`) confirms the condition.
*   **Verbose Error Data Extraction:** Forcing the database to generate an error message that explicitly includes the target sensitive data inside the text of the error itself (e.g., converting a string to an integer to trigger a verbose type-conversion error).

---

## 2. Exploiting Blind SQLi via Conditional Errors

### The Problem
In standard Blind SQL Injection, you look for differences in the page content when injecting true or false statements (e.g., a "Welcome back" message disappearing). However, many modern applications behave identically regardless of whether a query returns data or empty sets. Standard boolean-based blind techniques fail here because the visual interface remains completely static.

### The Solution
Instead of relying on the *content* of the query results, you can manipulate the query to control whether the database executes a malicious, error-inducing operation. By tying this operation to a specific truth condition, an unhandled database exception will alter the application's global response format (e.g., throwing a generic error page or changing the HTTP status code), allowing you to infer the truth of your condition.

---

## 3. Technical Mechanics & Proof of Concept (PoC)

To test for conditional errors, you can use conditional statements like `CASE` paired with a known error-inducing operation, such as a **divide-by-zero (`1/0`)** exception.

Consider an application that uses a tracking cookie (`TrackingId`) inside a backend query. We can inject the following test vectors:

### Vector 1: Evaluating a False Condition
```sql
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
```
*   **Mechanism:** The `CASE` statement checks if `1=2`. Since this is **false**, it executes the `ELSE` branch and returns the character `'a'`.
*   **Outcome:** The query executes safely without errors. The application returns its standard successful response (**HTTP 200**).

### Vector 2: Evaluating a True Condition
```sql
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```
*   **Mechanism:** The `CASE` statement checks if `1=1`. Since this is **true**, it executes the `THEN` branch and attempts to evaluate `1/0`.
*   **Outcome:** The database throws a runtime divide-by-zero exception. The application fails to handle the backend exception and returns an error response (**HTTP 500**).

### Summary of Behavioral Inference

| Injected Condition | Evaluated Branch | Database Behavior | HTTP Response Status | Inference |
| :--- | :--- | :--- | :--- | :--- |
| **`1=2` (False)** | `ELSE 'a'` | Success (No Error) | `200 OK` (Standard) | Injected condition is **False** |
| **`1=1` (True)** | `THEN 1/0` | Runtime Exception | `500 Internal Error` | Injected condition is **True** |

---

## 4. Character-by-Character Data Exfiltration

Once conditional error behavior is verified, you can systematically exfiltrate sensitive records (such as administrative passwords) by testing one character at a time using string manipulation functions like `SUBSTRING()`.

### Exfiltration Query Pattern
```sql
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END)='a
```

### Breakdown of the Attack Logic
1.  **Target Isolation:** The query targets rows where `Username = 'Administrator'`.
2.  **String Extraction:** `SUBSTRING(Password, 1, 1)` extracts exactly **1 character** starting at position **1** from the administrator's password.
3.  **Boolean Comparison:** It checks if that character's ASCII value is greater than character `'m'` (`> 'm'`).
4.  **Error Triggering:** 
    *   If the first character is greater than `'m'`, the condition is **true**, `1/0` executes, and the application throws an **HTTP 500** error.
    *   If the first character is `'m'` or lower, the condition is **false**, `'a'` is returned, and the application returns a normal **HTTP 200** response.
5.  **Iterative Automation:** By adjusting the index position in `SUBSTRING(Password, X, 1)` and sweeping through possible characters using a script or an automated tool (like Burp Intruder), you can reconstruct the complete plaintext password character by character.

---

## 5. Implementation Considerations

*   **Database Syntax Variance:** The payload structure varies significantly depending on the underlying database engine. For example, Oracle requires a `FROM dual` statement in subqueries and uses different error triggers, while Microsoft SQL Server, PostgreSQL, and MySQL have distinct behaviors regarding error propagation.
*   **Query Optimization Blocks:** Some modern database query planners use short-circuit evaluation. If the database engine determines it can optimize out a branch before evaluating it, the conditional error might not trigger as expected.
