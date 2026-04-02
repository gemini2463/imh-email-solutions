# Email Solutions (imh-email-solutions), v0.0.1

**Canonical name:** Email Solutions

Root-only WHM/cPanel + CWP plugin for outbound mail sanity checks.

## Current feature set

### DNS Checks (default tab)

Validates that outbound email-sending IP address(es) and the corresponding HELO name(s) have reasonable forward and reverse DNS:

- PTR (rDNS) exists for the sending IP
- PTR hostname resolves back to the sending IP (forward-confirmed rDNS)
- HELO hostname has A/AAAA
- HELO A/AAAA includes the sending IP (best practice; may be intentionally different in some environments)

### Where settings come from

- **cPanel/WHM (Exim):**
  - `/etc/mailips`
  - `/etc/mailhelo`
  - Reference: https://docs.cpanel.net/knowledge-base/email/how-to-configure-the-exim-outgoing-ip-address/

- **CWP (Postfix):**
  - Parses `/etc/postfix/master.cf` transport overrides for:
    - `smtp_bind_address`
    - `smtp_helo_name`
  - Reference: https://wiki.centos-webpanel.com/postfix-send-email-from-dedicated-ip-address

## Installation

Run as root:

```bash
curl -fsSL https://raw.githubusercontent.com/gemini2463/imh-email-solutions/master/install.sh | bash
```

## Paths

- **cPanel/WHM:** `/usr/local/cpanel/whostmgr/docroot/cgi/imh-email-solutions/index.php`
- **CWP:** `/usr/local/cwpsrv/htdocs/resources/admin/modules/imh-email-solutions.php`

## Files

- `index.php` — main UI
- `imh-email-solutions.php` — CWP module wrapper (includes `index.php`)
- `imh-email-solutions.conf` — WHM appconfig
- `imh-email-solutions.png` — icon
- `imh-email-solutions.js` — reserved for future
- `install.sh` — installer
