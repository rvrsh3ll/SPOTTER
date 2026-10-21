---
name: 'Disposable identity: atomicmail + Duck forwarding'
description: >-
  Use when the user wants a new standardized throwaway identity: a
  word-word-word-NN username with a matching @atomicmail.io inbox, an @duck.com
  address forwarding to it, and optionally a free Proton (Mail + VPN) account,
  logged for reuse in app signups.
---
> Run this end to end, steps 0 through 4 (Tor setup through Proton). Every request, DNS included, goes through Tor. You need a browser tool (e.g. Playwright MCP) to drive the signups. Pause and ask me at every captcha you can't solve, and at any phone, card, or SMS step.

# Disposable identity: atomicmail.io inbox + duck.com forwarding (+ optional Proton)

Produces one identity `<username>@atomicmail.io` plus `<username>@duck.com` forwarding to it, and optionally a free Proton account `<username>@proton.me` (Proton Mail + Proton VPN Free share one account). `<username>` = three random lowercase words + two digits (e.g. `eagleprairieplum20`). Every identity is logged in a private CSV on this machine.

## 0. Route everything through Tor (DNS included)

Do this once per machine, then verify it before every identity. If any check fails, stop. Do not fall back to a direct connection.

**Setup (Debian/Ubuntu):**
```bash
sudo apt install -y tor torsocks
sudo tee -a /etc/tor/torrc >/dev/null <<'EOF'
SocksPort 127.0.0.1:9050 IsolateSOCKSAuth
ControlPort 127.0.0.1:9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
EOF
sudo usermod -aG debian-tor "$USER"   # lets you read the control cookie; log out and back in
sudo systemctl restart tor
```

**Browser (the browser tool, for example Playwright MCP):** start it with a SOCKS5 proxy so hostnames resolve at the Tor exit, never locally.
- Playwright: `--proxy-server=socks5://127.0.0.1:9050`. With Chromium, `socks5://` already sends DNS through the proxy. Also pass `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"` so a misconfiguration fails closed instead of leaking DNS.
- Chrome/Chromium launched by hand: same two flags, plus `--disable-quic` and `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` to stop WebRTC and UDP leaks.
- Firefox: network.proxy.socks 127.0.0.1:9050, network.proxy.socks_remote_dns=true, network.trr.mode=5, media.peerconnection.enabled=false.
- Better still, when the agent can drive it: use Tor Browser itself, which handles all of this and reduces fingerprinting.

**Command-line tools:** run them as `torsocks <cmd>`, or use `curl --socks5-hostname 127.0.0.1:9050` (the `-hostname` part makes Tor resolve DNS). Never use plain `--socks5`, which resolves DNS locally.

**Verify before each identity (all three must pass):**
```bash
curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip   # expect "IsTor":true
```
- In the browser, open https://check.torproject.org and confirm "Congratulations".
- Open https://dnsleaktest.com (standard test) and confirm that no resolver belongs to your ISP or LAN.

**New circuit per identity**, so identities don't share an exit IP:
```bash
printf 'AUTHENTICATE %s\r\nSIGNAL NEWNYM\r\nQUIT\r\n' "$(xxd -p /run/tor/control.authcookie | tr -d '\n')" | nc 127.0.0.1 9051
```
Then wait about 10 seconds, re-run the curl check, and note the new exit IP in the CSV notes. Also clear cookies and site data between identities, or use a fresh browser profile for each one.

**Expect friction:** Atomic Mail and DuckDuckGo may show more captchas or block some exit nodes. If a site refuses, request a new circuit and retry up to 3 times, then stop and ask the user. Proton officially supports Tor (it has an onion address, https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion, reachable only through Tor). Proton may require human verification more often over Tor. Never switch to SMS or card verification to get past it.

## 1. Generate the identity
- Run `python3 ~/.disposable-identities/gen_identity.py "<purpose>"`. It prints the username/addresses as JSON and appends a row (with a random 20-char password) to `~/.disposable-identities/identities.csv` (mode 600).
- If the script is missing, recreate it: pick 3 words with `secrets.choice` from a ~150-word nature wordlist, append `secrets.randbelow(100):02d`, generate a 20-char password with upper/lower/digit/symbol, and append to the CSV with columns `created,username,atomicmail,duck_alias,password,purpose,status,atomicmail_seed_file,duck_status,notes`. Keep `~/.disposable-identities` at mode 700. Add a `proton_status` column when step 4 runs.
- Read the password from the CSV with Shell only when a signup step needs it. Never paste passwords or seed phrases into chat.

## 2. Create the Atomic Mail inbox (browser)
- Start at https://atomicmail.io, sign up with the exact username and the generated password. Name fields: derive first/last from the words (e.g. "Eagle", "Plum").
- If the name is taken, stop and generate a new identity (mark the old CSV row `status=taken`); don't improvise a variant.
- Signup shows a 12-word recovery seed phrase and downloads it to `~/Downloads`. Move that file to `~/.disposable-identities/seeds-<username>.txt` (mode 600) and record the path in the CSV.
- Expect an image-tap captcha; the subagent can usually pass it in 1-2 tries. No phone step was required (Oct 2026).
- Leave the inbox open in a tab; note its mailbox URL for later steps.

## 3. Create the Duck address (browser)
- Duck Email Protection requires the DuckDuckGo browser extension ("DuckDuckGo Search & Tracker Protection" from the Chrome Web Store). Install it once if missing, then delete the downloaded `.crx` from Downloads.
- Only the main personal `@duck.com` address is user-chosen; extra private addresses are random. So each identity needs its own Duck signup. If the extension is already signed in to a previous identity, sign out of Email Protection first (duckduckgo.com/email/settings, or the extension's Email Protection settings), then start a fresh signup.
- At https://duckduckgo.com/email/ choose Get Started, enter the exact username as the Duck address, and the atomicmail address as the forwarding address. Solve the duck-picking captcha.
- Verify via the "Confirm your forwarding address" email from support@duck.com in the Atomic Mail inbox (check spam). Duck logins use a one-time passphrase emailed to the forwarding address, so there is no Duck password to store.
- Tell the subagent to ignore Duck's autofill offers to generate random private addresses when typing emails on other sites.
- Update the CSV row: `status=duck_forwarding_active`.

## 4. Optional: free Proton account (Mail + VPN) (browser)
Run only when the user asks for Proton for this identity.
- Before starting, sign out of any Proton account already signed in on this machine browser (account.proton.me), so the new signup isn't linked to a previous identity.
- Start at https://account.proton.me/signup?plan=free . Choose the Free plan only; decline every upgrade or trial.
- Username: the exact `<username>` (domain `proton.me`; take `pm.me`/`protonmail.com` only if that's all it offers). If taken, stop and report; don't improvise.
- Password: the identity's generated password from the CSV.
- Human verification: choose the **Email** option and enter `<username>@duck.com`; read the code in the Atomic Mail tab (check spam). If Proton offers only SMS or a payment card, stop and report; do not enter a phone number or card.
- Recovery: set the recovery email to `<username>@duck.com` if asked. If Proton shows a recovery phrase or offers a recovery kit download, save it to `~/.disposable-identities/proton-recovery-<username>.txt` (mode 600) and remove it from Downloads.
- Skip the display-name and onboarding extras, or use the same derived first/last name.
- VPN: the same Proton account signs in to Proton VPN Free (https://protonvpn.com / the Proton VPN apps); no separate signup. Confirm the account shows VPN Free at https://account.proton.me/vpn/dashboard if it loads, but don't install a VPN client on this machine unless the user asks (it would reroute this machine's traffic).
- Update the CSV: `proton_status=active (<username>@proton.me, verified via duck)`.

## 5. Use it for app signups
- Register on the target site with `<username>@duck.com` (so the atomicmail address stays hidden). Read verification codes in the Atomic Mail tab.
- Record each site account in the CSV `notes` (site, account id, login method), and set `status` to the latest step.
- Never enter a phone number, payment detail, or real personal data without the user's say-so; stop and report the exact field instead. Don't use throwaway SMS services to get past phone checks. Don't pick options on a form that would misstate who the user is (e.g. claiming to be an employer); stop and ask.

## 6. Report to the user
- Give the addresses, what was created, and where the credentials are logged. Do not repeat passwords or seed phrases in chat unless the user asks for them.
