#!/usr/bin/env python3
"""
XSS Filter Bypass - CTF Challenge
Bypass the XSS filter to steal the admin cookie

This is an INTENTIONALLY VULNERABLE application for educational purposes.
"""

from flask import Flask, request, render_template_string, make_response
import re
import html

app = Flask(__name__)

# The secret flag stored in admin's cookie
ADMIN_FLAG = "CTF{xss_f1lt3r_byp4ss3d_l1k3_4_pr0}"

# XSS Filter - Blacklist approach (vulnerable!)
XSS_BLACKLIST = [
    r'<script',
    r'javascript:',
    r'onerror',
    r'onload',
    r'onclick',
    r'onmouseover',
    r'onfocus',
    r'onblur',
    r'alert',
    r'confirm',
    r'prompt',
    r'eval',
    r'document\.cookie',
    r'document\.location',
    r'window\.',
    r'<iframe',
    r'<embed',
    r'<object',
]

def xss_filter(user_input):
    """
    Filter user input to prevent XSS attacks.
    Uses blacklist approach - blocks known malicious patterns.
    """
    filtered = user_input

    for pattern in XSS_BLACKLIST:
        # Case-insensitive matching
        filtered = re.sub(pattern, '', filtered, flags=re.IGNORECASE)

    return filtered

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Guestbook - Share Your Thoughts!</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .post { border: 1px solid #ddd; padding: 15px; margin: 10px 0; background: #f9f9f9; }
        .post-content { margin-top: 10px; }
        input[type="text"], textarea { width: 100%; padding: 10px; margin: 10px 0; }
        input[type="submit"] { background: #28a745; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .admin-badge { background: #dc3545; color: white; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
        .notice { background: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 20px 0; }
        .protected { background: #d4edda; padding: 5px 10px; border-radius: 3px; font-size: 12px; }
    </style>
</head>
<body>
    <h1>Guestbook <span class="protected">Protected by XSS Filter v2.0</span></h1>

    <div class="notice">
        <strong>Security Notice:</strong> All posts are filtered for malicious content.
        Your data is safe with us! <br>
        <small>Admin visits this page regularly. Feel free to leave a message!</small>
    </div>

    <h2>Leave a Message</h2>
    <form method="POST">
        <input type="text" name="name" placeholder="Your Name" required><br>
        <textarea name="message" placeholder="Your Message" rows="4" required></textarea><br>
        <input type="submit" value="Post Message">
    </form>

    <h2>Recent Messages</h2>
    {% for post in posts %}
    <div class="post">
        <strong>{{ post.name }}</strong>
        {% if post.is_admin %}
        <span class="admin-badge">ADMIN</span>
        {% endif %}
        <small style="color: #666;">at {{ post.time }}</small>
        <div class="post-content">{{ post.content | safe }}</div>
    </div>
    {% endfor %}

    <hr>
    <p><small>We take security seriously. Our XSS filter blocks all known attack patterns!</small></p>
</body>
</html>
'''

# Simulated posts storage
posts = [
    {"name": "Admin", "content": "Welcome to our secure guestbook!", "time": "10:00 AM", "is_admin": True},
    {"name": "Alice", "content": "Great website! Very secure!", "time": "10:30 AM", "is_admin": False},
]

@app.route('/', methods=['GET', 'POST'])
def guestbook():
    if request.method == 'POST':
        name = request.form.get('name', 'Anonymous')
        message = request.form.get('message', '')

        # Apply XSS filter
        filtered_message = xss_filter(message)

        # Add post
        posts.insert(0, {
            "name": name[:50],  # Limit name length
            "content": filtered_message,
            "time": "Just now",
            "is_admin": False
        })

    return render_template_string(HTML_TEMPLATE, posts=posts)

@app.route('/admin')
def admin_panel():
    """
    Simulated admin panel that the admin bot visits.
    In a real CTF, this would be a bot that visits the page with the flag cookie.
    """
    resp = make_response(render_template_string(HTML_TEMPLATE, posts=posts))
    # Set the flag in the admin's cookie
    resp.set_cookie('flag', ADMIN_FLAG, httponly=False)  # Note: httponly=False for the challenge
    return resp

@app.route('/receive', methods=['POST'])
def receive():
    """Endpoint to receive stolen cookies (for CTF demonstration)"""
    data = request.json
    if data and 'cookie' in data:
        print(f"[!] Received stolen cookie: {data['cookie']}")
        if 'flag' in data['cookie']:
            return {"status": "success", "message": "Flag received!"}
    return {"status": "received"}

if __name__ == '__main__':
    print("[*] XSS Filter Bypass Challenge")
    print("[*] Running on http://localhost:5001")
    print("[*] Admin panel: http://localhost:5001/admin")
    print("[*] Cookie receiver: http://localhost:5001/receive")
    app.run(host='0.0.0.0', port=5001, debug=False)
