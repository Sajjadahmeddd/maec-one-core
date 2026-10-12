# Go-live runbook — single sign-on at auth.mirageaec.com and et.mirageaec.com

For the person doing the cutover, on the VPS over SSH. Follow it top to bottom.
Every command has a comment under it saying what it does. Nothing here
contains a real secret: each one is generated on the server, with the command
shown. Never paste a generated secret into a chat, a ticket or a commit.

**The shape of it.** Core (sign-in, at `auth.mirageaec.com`) and the new,
gated Engineering Tools both start *next to* the old Engineering Tools stack,
which keeps serving `et.mirageaec.com` the whole time. Going live is one line
in Caddy: point `et.mirageaec.com` at the new stack. Rolling back is the same
line, back.

```
                  ┌─ auth.mirageaec.com ─▶ 127.0.0.1:8001 ─▶ Core           (new)
Caddy (host:443) ─┤
                  └─ et.mirageaec.com  ─▶ 127.0.0.1:80   ─▶ old ET stack   (today)
                                       └▶ 127.0.0.1:8081 ─▶ new ET stack   (after step 7)

new ET backend ── http://maec-core:8000 ──▶ Core          (Docker network maec_core_net)
```

Placeholders you fill in: `<NEW_REPO>` (the new GitHub repository for gated
Engineering Tools), `<GITHUB_OWNER>`, `<OLD_ET_FOLDER>` (where the old
Engineering Tools stack lives on the VPS) and `<VPS_IP>`.

**Never overwrite a file that exists.** Every copy below uses `cp -n`, which
refuses to replace an existing file. If a step says a file already exists,
stop and look at it before doing anything else.

---

## 1. Before you start — write down the old stack, change nothing

```bash
cd <OLD_ET_FOLDER> && git log -1 --oneline
# Records the commit the old Engineering Tools stack is running. Write it down:
# it is what you are protecting, and what a rollback returns to.

docker ps --format '{{.Names}}\t{{.Ports}}\t{{.Image}}'
# Lists running containers. Confirm the old stack's frontend publishes
# 127.0.0.1:80->80/tcp, and note every container name.

docker network ls
# Lists Docker networks. Note the old stack's network (maec_maec_net).

docker network inspect maec_maec_net --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
# Prints its address range. Expect 172.30.57.0/24.

sudo cat /etc/caddy/Caddyfile
# Shows the current Caddy configuration. Copy the et.mirageaec.com block into
# your notes exactly as it is — step 7 changes one line of it, step 9 restores it.

sudo cp -n /etc/caddy/Caddyfile /etc/caddy/Caddyfile.before-maec-one
# Keeps a copy of today's Caddyfile. -n: if that copy already exists from an
# earlier attempt, it is left alone rather than overwritten.
```

Then, in the Render dashboard, confirm the service behind
`engineeringtools.mirageaec.com` is **Suspended**. Its copy of the old `main`
has the open file-path hole, and nothing in this runbook replaces it — it
must simply not be serving.

```bash
curl -sI https://engineeringtools.mirageaec.com | head -1
# Asks the old Render address for its status. Anything but a working app
# (a Render "suspended" page, an error, no answer) is what you want.
```

---

## 2. DNS

In the DNS provider for mirageaec.com, add an **A record** for
`auth.mirageaec.com` pointing at the VPS. Leave `et.mirageaec.com` alone — it
already points at the VPS.

```bash
curl -4 -s ifconfig.me; echo
# Prints the VPS's public IPv4 address: <VPS_IP>.

dig +short auth.mirageaec.com
# Must print the same address. If it prints nothing, wait for DNS to spread and
# try again — Caddy cannot get a certificate for auth.mirageaec.com until it does.
```

---

## 3. Core

### 3a. Check its address ranges are free

```bash
docker network inspect $(docker network ls -q) --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}'
# Lists every Docker network and its range. Nothing may already use 10.231.0.0/24
# or 10.231.1.0/24 — Core's two networks (OPEN-DECISIONS #21).

ip route | grep -E '^10\.231\.' || echo "10.231.x.x is free"
# Checks the host's own routes for the same ranges. "free" is what you want.

ss -ltn | grep -E ':8001\b' || echo "port 8001 is free"
# Checks nothing on the host already listens on 8001, where Core is published.
```

If anything is in use, stop: the ranges are fixed in
`deploy/compose.example.yml`, and changing them is a change to decision #21.

### 3b. Get the code

```bash
sudo mkdir /opt/maec-one-core && sudo chown "$USER": /opt/maec-one-core
# Makes Core's own folder, owned by you, so nothing below needs sudo. mkdir
# refuses if the folder already exists — stop and look at what is there.

git clone -b gate https://github.com/Sajjadahmeddd/maec-one-core.git /opt/maec-one-core
# Downloads Core's gate branch into it.

cd /opt/maec-one-core && git log -1 --oneline
# Shows the commit you are deploying. Write it down.
```

### 3c. Generate the secrets

Run each command **once**, on the server, and paste its output straight into
the env file in 3d. Do not save them anywhere else.

```bash
openssl rand -hex 24
# POSTGRES_PASSWORD: the database password. Hex, so nothing in it needs escaping.

python3 -c "import secrets; print(secrets.token_urlsafe(48))"
# SESSION_SECRET: signs the session cookie. Changing it later signs everyone out.

echo "OIDC_PRIVATE_KEY='$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | awk 'NF {printf "%s\\n", $0}')'"
# OIDC_PRIVATE_KEY: prints the whole finished line, single quotes included.
# Paste it as it is: without the quotes, Docker Compose refuses the file.

python3 -c "import secrets; print(secrets.token_urlsafe(32))"
# The new gate secret for Engineering Tools. It goes into BOTH Core's
# GATE_SECRETS (3d) and Engineering Tools' MAEC_GATE_SECRET (6d). Never the
# one used during development: that one has been pasted in a chat.

python3 -c "import secrets; print(secrets.token_urlsafe(15) + 'Aa1!')"
# BOOTSTRAP_ADMIN_PASSWORD: the first Global Admin's starting password. The
# 'Aa1!' guarantees the upper/lower/digit/symbol the password rule asks for.
```

### 3d. Fill the settings and start

```bash
cd /opt/maec-one-core
# Works in Core's folder from here on.

cp -n deploy/env.production.example deploy/env.production && ls -l deploy/env.production
# Makes the server's own settings file from the template. -n: an existing one
# is never overwritten. The ls shows it is there.

chmod 600 deploy/env.production
# Lets only the file's owner read it: it is about to hold secrets.

nano deploy/env.production
# Fill in every <generate on the server> with the outputs from 3c, and
# BOOTSTRAP_ADMIN_EMAIL with a named person's address. Leave MAEC_ENV,
# CORE_PUBLIC_URL and SESSION_COOKIE_DOMAIN as the template has them.

grep -n '<' deploy/env.production | grep -v '^[0-9]*:#' || echo "no placeholders left"
# Finds any line still holding a <placeholder>. "no placeholders left" is what you want.

cp -n deploy/compose.example.yml deploy/compose.yml
# Makes the server's compose file from the example. -n: never overwrites.

docker compose -f deploy/compose.yml --env-file deploy/env.production up -d --build
# Builds Core and starts it with its own PostgreSQL. It needs no other app.

docker compose -f deploy/compose.yml --env-file deploy/env.production ps
# Shows both containers. Wait until core reads "(healthy)" — under a minute.

docker compose -f deploy/compose.yml --env-file deploy/env.production logs core | grep -E 'Running upgrade|seed:|RuntimeError'
# Shows the migrations, the seed and any refusal. You want "seed: created ..."
# and "Global Admin is <your address>". A RuntimeError names the setting that
# is wrong; fix it and run the up command again.

curl -s http://127.0.0.1:8001/api/health; echo
# Asks Core directly. Expect "status":"ok" and "database":"ok".
```

### 3e. Caddy

Add this block to `/etc/caddy/Caddyfile`, beside the others. Change nothing else.

```
auth.mirageaec.com {
    reverse_proxy localhost:8001
}
```

```bash
sudo nano /etc/caddy/Caddyfile
# Opens the Caddyfile. Add the block above; leave every other block exactly as it is.

sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
# Checks the file before Caddy uses it. "Valid configuration" is what you want.

sudo systemctl reload caddy
# Makes Caddy read the file again, without dropping anyone's connection. Caddy
# fetches a certificate for auth.mirageaec.com the first time it is asked.
```

---

## 4. Check Core on its own

In a browser, open **https://auth.mirageaec.com** and sign in as the
bootstrap admin. You land on the admin panel.

Open the developer tools → **Application** (Chrome) or **Storage** (Firefox)
→ **Cookies** → `https://auth.mirageaec.com`. The cookie `maec_session` must
show:

* Domain **`.mirageaec.com`** — not `auth.mirageaec.com`;
* **Secure** ticked, **HttpOnly** ticked, SameSite **Lax**.

```bash
cd /opt/maec-one-core && docker compose -f deploy/compose.yml --env-file deploy/env.production exec core-db psql -U maec_core -d maec_identity -c "select created_at, actor_email, action, ip from audit_logs order by created_at desc limit 3"
# Shows the last three audit rows. The sign-in's ip must be YOUR public address.
# If it reads 10.231.x.x, the trusted-proxy setting is wrong (OPEN-DECISIONS #6, #21): stop.
```

---

## 5. Set Core up

### 5a. Replace the bootstrap password

In the admin panel → **Users & Access** → your own account → **Account** →
type a temporary password → reset. You are signed out. Sign in with it, and
Core makes you choose your own. Then:

```bash
cd /opt/maec-one-core && nano deploy/env.production
# Empty the BOOTSTRAP_ADMIN_PASSWORD value. The seed never overwrites an existing
# password, but a password should not sit in a file once nobody needs it.
```

### 5b. Engineering Tools' address

```bash
docker compose -f deploy/compose.yml --env-file deploy/env.production exec core-db psql -U maec_core -d maec_identity -c "UPDATE applications SET base_url = 'https://et.mirageaec.com' WHERE key = 'engineering';"
# Tells Core where Engineering Tools lives. Its launcher tile opens it, and after
# sign-in people are sent back only to this exact address. Expect "UPDATE 1".
```

### 5c. Everyone who uses Engineering Tools today

The old app had **one shared password**. After the switch, only people with
their own account *and* an Engineering Tools seat can get in. Make the list
first — everyone who uses it today — and for each person, in **Users &
Access**:

1. **Add user**: name, email, department, and an **initial password**. Core
   marks it "must change password": they choose their own at first sign-in.
2. **Roles** → *Normal User / Engineer*, scope type `application`, scope id
   `engineering` → grant.
3. **Application seats** → **Engineering Tools** → give a seat.

**How each person gets their first password** — decide before step 7, and
write the plan down:

* the initial password goes to the person by a different channel from the one
  that tells them their address — in person, or by phone; never in the same
  email or chat message;
* it is single-use in effect: Core refuses everything until they replace it;
* tell them the day and time of the switch, and that the old shared password
  stops working then.

---

## 6. The new Engineering Tools — running, not yet public

### 6a. Its repository

On the laptop that has the finished `gate-client` branch:

```bash
cd HAP_mirageaec && git log -1 --oneline gate-client
# Shows the gate-client commit you are about to publish. Write it down.

git push https://github.com/<GITHUB_OWNER>/<NEW_REPO>.git gate-client:main
# Publishes gate-client as main of the new, empty repository. Create <NEW_REPO>
# on GitHub first, empty — no README, no licence — so this is its first commit.
```

### 6b. Its folder on the VPS — never inside the old one

```bash
sudo mkdir /opt/<NEW_REPO> && sudo chown "$USER": /opt/<NEW_REPO>
# Makes the new Engineering Tools' own folder, next to — never inside —
# <OLD_ET_FOLDER>. mkdir refuses if it exists: stop and look.

git clone https://github.com/<GITHUB_OWNER>/<NEW_REPO>.git /opt/<NEW_REPO>
# Downloads the new Engineering Tools into it.

cd /opt/<NEW_REPO> && git log -1 --oneline
# Must show the commit you wrote down in 6a.
```

### 6c. Check it cannot touch the old stack

The old stack is the Compose project `maec`, on port 80, network
`maec_maec_net` (172.30.57.0/24). The new one must differ in all of them, or
starting it would replace or collide with the old one.

```bash
grep -nE '^name:|127\.0\.0\.1:[0-9]+:|subnet:|maec_core_net|image:' docker-compose.yml
# Shows the new stack's project name, published port, range, Core network and
# image names. You need: a name that is NOT "maec"; 127.0.0.1:8081 (not 80);
# a subnet that is NOT 172.30.57.0/24; maec_core_net joined as external; and
# image names different from the old stack's. If any is wrong, stop.
```

### 6d. Its settings

```bash
ls -l .env.maec 2>/dev/null && echo "EXISTS — stop and look" || echo ".env.maec is absent"
# Checks first, as its own step: an existing .env.maec is never overwritten.

cp -n .env.maec.example .env.maec && chmod 600 .env.maec
# Makes the new stack's settings file from its template; -n never overwrites.
# chmod: readable by its owner only.

nano .env.maec
# Set, at least:
#   CORE_URL=http://maec-core:8000                (Core, over maec_core_net)
#   CORE_PUBLIC_URL=https://auth.mirageaec.com
#   MAEC_APP_KEY=engineering
#   MAEC_GATE_SECRET=<the gate secret from 3c — the same value as Core's GATE_SECRETS>
# and everything else its README-docker.md asks for. Its entrypoint refuses to
# start on a placeholder or a short secret.
```

### 6e. Start it

```bash
docker compose up -d --build
# Builds and starts the new stack on 127.0.0.1:8081. Core must already be
# running: this joins Core's network, maec_core_net.

docker compose ps
# Wait until every container reads "(healthy)" or "Up".

docker ps --format '{{.Names}}\t{{.Ports}}' | grep -E ':80->|:8081->'
# Shows BOTH stacks running: the old one on 127.0.0.1:80, the new one on 127.0.0.1:8081.
```

### 6f. Check it from the VPS shell, before anyone can reach it

This sends a request to the new stack exactly as Caddy will once
`et.mirageaec.com` points at it — the host it was asked for, https, and a
visitor's address:

```bash
curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  -H 'Host: et.mirageaec.com' -H 'X-Forwarded-Host: et.mirageaec.com' \
  -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-For: 203.0.113.10' \
  'http://127.0.0.1:8081/some/page?x=1'
# Asks the new Engineering Tools for a page with no session. It must answer
# with a redirect to Core's sign-in, carrying the exact page to come back to.
```

The line printed must be exactly:

```
302 https://auth.mirageaec.com/?next=https%3A%2F%2Fet.mirageaec.com%2Fsome%2Fpage%3Fx%3D1
```

* `503` and "MAEC One is unavailable": the new stack cannot reach Core —
  check it joined `maec_core_net` and that `CORE_URL` is `http://maec-core:8000`.
* `next=http%3A…` (plain http) or another host in `next`: the new stack is
  not reading the forwarded address correctly. Do not switch.
* The old stack answers? Check `docker ps`: 8081 must be the new one.

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:80/
# Confirms the old stack still answers on port 80, untouched.
```

---

## 7. Switch

Change **one line** of the `et.mirageaec.com` block — the port.

Before (today, the block you noted in step 1):

```
et.mirageaec.com {
    reverse_proxy localhost:80
}
```

After:

```
et.mirageaec.com {
    reverse_proxy localhost:8081
}
```

If the block you noted has more lines than this, keep them all and change only
`localhost:80` → `localhost:8081`.

```bash
sudo nano /etc/caddy/Caddyfile
# Opens the Caddyfile. Change localhost:80 to localhost:8081 in the
# et.mirageaec.com block, and nothing else.

sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
# Checks the change before it is used. "Valid configuration" is what you want.

sudo systemctl reload caddy
# Switches et.mirageaec.com to the new stack, without dropping connections.
```

---

## 8. The checks

In an **incognito / private window**, so no old cookie interferes. The same
five checks as prompt 10, Part C, now on the real addresses:

1. **Sign in, land back.** Open `https://et.mirageaec.com/` → you are sent to
   `https://auth.mirageaec.com/?next=…` → sign in as an engineer with a seat
   → you land back on Engineering Tools, on the page you asked for.
2. **No second sign-in.** Open another Engineering Tools page in a new tab of
   the same window → it opens directly.
3. **No seat, no entry.** In the admin panel (a different browser), remove
   that engineer's Engineering Tools seat → their next click in Engineering
   Tools shows "no access". Give the seat back → their next click works.
4. **One sign-out, everywhere.** Sign out at `https://auth.mirageaec.com` →
   the next click in Engineering Tools sends them to sign in again.
5. **The launcher.** At `https://auth.mirageaec.com`, the Engineering Tools
   tile opens `https://et.mirageaec.com` and lets them straight in.

All five pass: you are live. Any one fails: step 9, now.

---

## 9. Rollback — if any check in step 8 fails

```bash
sudo nano /etc/caddy/Caddyfile
# In the et.mirageaec.com block, change localhost:8081 back to localhost:80.
# Nothing else.

sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
# Checks the file. "Valid configuration" is what you want.

sudo systemctl reload caddy
# Points et.mirageaec.com at the old stack again. It is serving within seconds.
```

Leave Core and the new stack running: you will want them to find out what
went wrong. Nothing about the old stack changed at any point, so nothing about
it needs restoring.

---

## 10. Later — after a week of real use has gone well

```bash
cd <OLD_ET_FOLDER> && docker compose down
# Stops the old Engineering Tools stack and removes its containers. Its
# folder, code and images stay, in case you need to look back.
```

Keep `<OLD_ET_FOLDER>` for a while longer before deleting it. Then remove the
`engineeringtools.mirageaec.com` record from DNS, and delete the suspended
Render service.

---

## If Core goes down

Engineering Tools shows **"MAEC One is unavailable"** on every page until Core
is back: it checks every request with Core, and it fails closed — nobody gets
in unchecked. Bring Core back:

```bash
cd /opt/maec-one-core && docker compose -f deploy/compose.yml --env-file deploy/env.production ps
# Shows whether core and core-db are running and healthy.

docker compose -f deploy/compose.yml --env-file deploy/env.production logs --tail 50 core
# Shows Core's last 50 log lines — a refusal names the setting at fault.

docker compose -f deploy/compose.yml --env-file deploy/env.production up -d
# Starts whatever is stopped. Engineering Tools recovers on its next request.
```

---

## Adding the next app

For an app that will live at `<app>.mirageaec.com`:

1. **Register it in Core** — a row in `applications` (key, name,
   `status = 'live'`), its permissions, and a subscription for the
   organisation. (No screen for this yet; SQL, as in 5b.)
2. **Set its `base_url`** — `https://<app>.mirageaec.com`, as in 5b. Without
   it, people are not sent back to it after sign-in.
3. **Add a gate secret** — generate one (3c), add it to Core's
   `GATE_SECRETS` as `,<app_key>=<secret>`, restart Core
   (`docker compose … up -d`), and put the same value in the app's settings.
4. **Join `maec_core_net`** — in the app's compose file, as an external
   network (see the README's Deploying section); it calls
   `http://maec-core:8000`.
5. **Add the gate middleware** — every request checked with Core, as
   Engineering Tools does (`backend/maec_auth/` in its repository).
6. **Add a Caddy block** — `<app>.mirageaec.com { reverse_proxy
   localhost:<its port> }`, published on `127.0.0.1` only. Validate, reload.

Then give people seats on it in **Users & Access**.
