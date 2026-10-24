# PortSwigger Web Security Academy: SQL Injection (SQLi)

## SQL Injection UNION Attacks

### Vulnerability Explanation
When an application is vulnerable to SQL injection, the `UNION` keyword can be used to execute one or more additional `SELECT` queries and append the results to the original query's response. This allows an attacker to extract data from other tables within the database. 

For a `UNION` attack to be successful, two strict structural requirements must be met:
1. The injected query must return the **same number of columns** as the original query.
2. The **data types** of the corresponding columns must be compatible between the original and injected queries.

---

### Target Query Structure
The application executes a query similar to the following to retrieve and display data:

```sql
SELECT item_name, item_description FROM products WHERE category = 'Gift_Injected_Point';
```

When a `UNION` payload is injected, the resulting database query looks like this:

```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2;
```

---

### Exploitation Payload
To carry out the attack, you must first determine the number of columns required using one of two common techniques.

#### Method 1: The `ORDER BY` Technique
Inject a series of `ORDER BY` clauses, incrementing the specified column index until the application returns an error or a noticeable difference in the response.

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```
*If `ORDER BY 3` triggers an error such as `"The ORDER BY position number 3 is out of range of the number of items in the select list"`, you know the original query returns exactly 2 columns.*

#### Method 2: The `UNION SELECT NULL` Technique
Submit a series of `UNION SELECT` payloads, gradually incrementing the number of `NULL` values until the query succeeds without a database error.

```sql
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
```
*`NULL` is used because it is convertible to almost every common data type, maximizing the chance of a successful match regardless of individual column types.*

---

### Key Takeaways
* **Two Conditions:** A `UNION` attack requires matching both the exact column count and compatible data types of the original query.
* **Comment Tokens:** The `--` syntax is used to comment out the remainder of the original SQL query so it does not interfere with the injection payload.
* **NULL Flexibility:** Using `NULL` values avoids data-type mismatch errors while discovering the correct column count.
* **Error Analysis:** If the column counts do not match, the database will fail with errors indicating an unequal number of expressions or out-of-range positions.
