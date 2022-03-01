# HTTP Intercept

A multithreaded HTTP intercepting proxy written in pure Python (standard library only).

Designed for traffic analysis, security research, and understanding how HTTP proxies work under the hood.

---

## Features

### Passive mode

- Forwards all HTTP traffic transparently.
- Extracts and logs PII-like data found in requests and responses:
  - Credentials (username, password)
  - Email addresses
  - Cookies (request and response)
  - Credit card numbers
  - Social Security numbers
  - Street addresses, city, state
  - US phone numbers
- Output: `info_1.txt`

### Active mode

- Injects a small JavaScript beacon into every HTML response.
- The beacon calls back to the proxy with the client's **user agent**, **screen resolution**, and **browser language**.
- Optionally serves a `custom_page.html` for a specified target domain.
- Output: `info_2.txt`

---

## Requirements

Python 3.8+ — standard library only, no external packages needed.

---

## Usage

```bash
# Passive mode: log traffic on 127.0.0.1:8080
python proxy.py -m passive 127.0.0.1 8080

# Active mode: inject JS beacon and intercept login.example.com
python proxy.py -m active 127.0.0.1 8080 login.example.com
```

Then configure your browser or system proxy to `127.0.0.1:8080`.

### Arguments

| Argument | Description |
|----------|-------------|
| `-m passive\|active` | Operation mode (required) |
| `<listen_ip>` | IP address to bind |
| `<listen_port>` | Port to bind (1025–65535) |
| `[domain]` | Target domain for custom page (active mode only) |

---

## Custom page

In active mode, if a target domain is specified, the proxy serves `custom_page.html` instead of forwarding the request. Edit this file to customise the served page.

---

## Log format

**Passive (`info_1.txt`)**
```
2024-01-15 14:23:01 -- From: http://example.com/login
Email:      user@example.com
Password:   hunter2
Request-Cookie:  session=abc123
```

**Active (`info_2.txt`)**
```
2024-01-15 14:23:05 -- From: http://example.com
user_agent:  Mozilla/5.0 ...
screen:      1920*1080
lang:        en-US
```

---

## Notes

- Only HTTP (not HTTPS) is intercepted. The proxy passes HTTPS `CONNECT` tunnels through unchanged.
- The proxy binds to ports ≥ 1025, so root privileges are not required.
- Use only on networks and systems you own or have explicit permission to test.

## License

MIT
