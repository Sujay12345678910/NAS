# pwgen

Password generator with an age-encrypted vault on your NAS, usable from the
terminal (`sync.py`) or a browser (`web.py`).

```
pwgen/
├── sync.py            command line, and the shared core the web server imports
├── web.py             web server (Python standard library only)
└── static/
    ├── login.html  generate.html  vault.html
    ├── css/style.css  ← you write this one
    ├── js/            common.js  login.js  generate.js  vault.js
    ├── vendor/age.js  age for the browser, pinned (see vendor/README.md)
    ├── fonts/         IBM Plex Sans + JetBrains Mono, self-hosted
    └── favicon.svg
```

## Requirements

Python 3.9+, paramiko and age, on whichever machine runs `web.py`:

```sh
sudo apt install python3-paramiko age      # Raspberry Pi OS / Debian
sudo pacman -S python-paramiko age         # Arch
```

Anyone signing in through the browser needs a NAS account that allows
password login over SSH. Accounts that only allow SSH keys can use `sync.py`.

## Run the web version

```sh
python3 web.py --host 192.168.0.99 --trust-host   # once: check and save the NAS fingerprint
python3 web.py --host 192.168.0.99                # serves http://127.0.0.1:8080
```

If `web.py` runs on the Pi itself, use `--host 127.0.0.1`.

**On the same machine:** open http://localhost:8080.

**From your other devices:** put Tailscale in front for HTTPS:

```sh
sudo tailscale serve --bg --https=8443 http://127.0.0.1:8080
```

Then open `https://<machine-name>.<tailnet>.ts.net:8443`.
Your NAS is shared with friends over Tailscale, so limit who can use the site:

```sh
python3 web.py --host 127.0.0.1 --allow-tailscale-user you@example.com
```

**Quick test from your laptop without Tailscale serve:**
`ssh -L 8080:127.0.0.1:8080 admin@192.168.0.99`, then open http://localhost:8080.

## What the server can and can't see

| | Server sees it? |
|---|---|
| Your NAS password | Yes, in memory while you're signed in (it signs in to the NAS as you). Dropped on sign-out or after 15 idle minutes |
| New passwords | Yes, once, at the moment it generates and encrypts them |
| Your stored passwords | **No**. The Vault page decrypts them in your browser |
| Your age private key | **No**. It never leaves the browser tab |

Other protections: wrong-password lockout (5 per 15 minutes), cookies that are
HttpOnly and SameSite=Strict, a strict Content-Security-Policy (no inline
scripts or styles, nothing loaded from other sites), no unknown NAS host keys,
and sessions bound to the Tailscale account that created them.

## Limits

- The browser can only decrypt `age1…` keys. Records encrypted only to an SSH
  key need `sync.py reveal`.
- Signing in through the web needs the NAS to be reachable. Once you're signed
  in, generated passwords are kept on the server if the NAS drops, and pushed
  when it's back.
