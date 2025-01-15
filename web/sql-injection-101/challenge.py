#!/usr/bin/env python3
"""
SQL Injection 101 - Vulnerable Login Application
CTF Challenge: Bypass authentication to retrieve the flag

This is an INTENTIONALLY VULNERABLE application for educational purposes.
NEVER use this code in production!
"""

import sqlite3
import hashlib
from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

# Initialize database with users and flag
def init_db():
    conn = sqlite3.connect('/tmp/challenge.db')
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    ''')

    # Create secrets table (contains the flag)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            name TEXT,
            value TEXT
        )
    ''')

    # Insert admin user with hashed password
    admin_password = hashlib.md5(b'sup3r_s3cr3t_p4ssw0rd_n0b0dy_w1ll_gu3ss!').hexdigest()
    try:
        cursor.execute(f"INSERT INTO users (username, password, role) VALUES ('admin', '{admin_password}', 'administrator')")
    except sqlite3.IntegrityError:
        pass

    # Insert regular user
    try:
        user_password = hashlib.md5(b'userpassword123').hexdigest()
        cursor.execute(f"INSERT INTO users (username, password, role) VALUES ('guest', '{user_password}', 'user')")
    except sqlite3.IntegrityError:
        pass

    # Insert the flag
    try:
        cursor.execute("INSERT INTO secrets (name, value) VALUES ('flag', 'CTF{sql_1nj3ct10n_m4st3r_2024}')")
    except sqlite3.IntegrityError:
        pass

    conn.commit()
    conn.close()

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login Portal</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 10px 0; }
        input[type="submit"] { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .error { color: red; }
        .success { color: green; }
        .flag { background: #ffd700; padding: 10px; font-family: monospace; }
    </style>
</head>
<body>
    <h1>Secure Login Portal</h1>
    <p>Welcome to the ultra-secure login system. Only authorized personnel allowed!</p>

    {% if message %}
    <p class="{{ message_type }}">{{ message }}</p>
    {% endif %}

    {% if flag %}
    <div class="flag">
        <strong>Secret Flag:</strong> {{ flag }}
    </div>
    {% else %}
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <input type="submit" value="Login">
    </form>
    {% endif %}

    <hr>
    <p><small>Version 1.0 - Definitely Secure&trade;</small></p>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULNERABLE: Direct string formatting in SQL query
        # This is the vulnerability we exploit!
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        try:
            conn = sqlite3.connect('/tmp/challenge.db')
            cursor = conn.cursor()
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()

            if user:
                # Check if admin
                if user[3] == 'administrator':
                    # Admin gets the flag
                    conn = sqlite3.connect('/tmp/challenge.db')
                    cursor = conn.cursor()
                    cursor.execute("SELECT value FROM secrets WHERE name = 'flag'")
                    flag = cursor.fetchone()[0]
                    conn.close()
                    return render_template_string(HTML_TEMPLATE, flag=flag, message="Welcome Administrator!", message_type="success")
                else:
                    return render_template_string(HTML_TEMPLATE, message="Login successful, but you're not admin!", message_type="error")
            else:
                return render_template_string(HTML_TEMPLATE, message="Invalid credentials!", message_type="error")
        except Exception as e:
            return render_template_string(HTML_TEMPLATE, message=f"Database error: {str(e)}", message_type="error")

    return render_template_string(HTML_TEMPLATE)

if __name__ == '__main__':
    init_db()
    print("[*] Starting vulnerable login application on http://localhost:5000")
    print("[*] This is an intentionally vulnerable application for CTF practice")
    app.run(host='0.0.0.0', port=5000, debug=False)
