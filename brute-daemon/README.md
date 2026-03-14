# brute-daemon

A honeypot daemon that listens on common service ports, captures plaintext credentials from brute-force attempts, and forwards them to the Brute API.

## Supported Protocols

| Protocol  | Port(s)   |
|-----------|-----------|
| SSH       | 22        |
| FTP       | 21        |
| Telnet    | 23        |
| SMTP      | 25        |
| SMTPS     | 465       |
| POP3      | 110       |
| IMAP      | 143       |
| IMAPS     | 993       |
| LDAP      | 389       |
| LDAPS     | 636       |
| HTTP      | 80, 8080  |
| MQTT      | 1883      |
| MySQL     | 3306      |
| PostgreSQL| 5432      |
| Redis     | 6379      |

## Setup

**1. Move your real SSH daemon off port 22** (e.g. to 2222) so the honeypot can claim it:

```
Port 2222
```

Restart sshd after changing `/etc/ssh/sshd_config`.

**2. Set environment variables:**

```env
ADD_ATTACK_ENDPOINT=https://your-api/attack/add
BEARER_TOKEN=your-token
```

**3. Open all honeypot ports** in your firewall / cloud security group (inbound TCP from `0.0.0.0/0`).

**4. Run the daemon:**

```bash
cargo run --release
```

## Notes

- All authentication attempts are rejected — no real service is exposed.
- Loopback connections (`127.0.0.1`, `::1`) are ignored and not forwarded.
- SMTPS, IMAPS, and LDAPS use a self-signed TLS certificate generated at startup.
