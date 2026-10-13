# Go-live runbook — single sign-on at auth.mirageaec.com and engtools.mirageaec.com

For the person doing the cutover, on the VPS over SSH. Follow it top to bottom.
Every command has a comment under it saying what it does. Nothing here
contains a real secret: each one is generated on the server, with the command
shown. Never paste a generated secret into a chat, a ticket or a commit.

**The shape of it.** Core (sign-in, at `auth.mirageaec.com`) and the new,
gated Engineering Tools (at its own new address, `engtools.mirageaec.com`)
start *next to* everything already on the VPS. Going live is **adding two
blocks** to the Caddyfile; nothing already in it changes. The old Engineering
Tools keeps serving `et.mirageaec.com` exactly as today, until real users have
moved and it is retired, as a separate, later step (step 10). Rolling back is
removing the `engtools.mirageaec.com` block.

```
                  ┌─ et.mirageaec.com        ─▶ 127.0.0.1:8080 ─▶ old Engineering Tools (project "maec"), unchanged
                  ├─ promanage.mirageaec.com ─▶ 127.0.0.1:8081 ─▶ Project Management (project "promanage"), unchanged
Caddy (host:443) ─┤
                  ├─ auth.mirageaec.com      ─▶ 127.0.0.1:8001 ─▶ Core                  (new)
                  └─ engtools.mirageaec.com  ─▶ 127.0.0.1:8082 ─▶ new Engineering Tools (new)

new ET backend ── http://maec-core:8000 ──▶ Core          (Docker network maec_core_net)
```

Placeholders you fill in: `<NEW_REPO>` (the new GitHub repository for gated
Engineering Tools), `<GITHUB_OWNER>`, `<OLD_ET_FOLDER>` (where the old
Engineering Tools stack lives on the VPS) and `<VPS_IP>`.

**Never overwrite a file that exists.** Every copy below uses `cp -n`, which
refuses to replace an existing file. If a step says a file already exists,
stop and look at it before doing anything else.

---

## 1. Before you start — write down what is running, change nothing

```bash
sudo ss -ltnp | grep -E ':(8001|8082)\b' || echo "8001 and 8082 are free"
# Checks, before anything is started, that nothing listens on 8001 (Core) or
# 8082 (the new Engineering Tools). "free" is what you want; anything listed —
# with the process holding it — means stop and find out what it is.

sudo ss -ltnp | grep -E ':(8080|8081)\b'
# Shows the two ports already in use and by whom: 8080, the old Engineering
# Tools; 8081, Project Management. Neither is touched by anything below.

cd <OLD_ET_FOLDER> && git log -1 --oneline
# Records the commit the old Engineering Tools is running. Write it down.

docker ps --format '{{.Names}}\t{{.Ports}}\t{{.Image}}'
# Lists running containers. Note the old Engineering Tools' (project "maec",
# 127.0.0.1:8080) and Project Management's (project "promanage", 127.0.0.1:8081).

docker network inspect $(docker network ls -q) --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}'
# Lists every Docker network and its range. Note them: Core uses 10.231.0.0/24
# and 10.231.1.0/24, the new Engineering Tools 10.231.2.0/24 — none may be in use.

sudo cat /etc/caddy/Caddyfile
# Shows today's Caddy configuration. Expect the global block with
# "protocols h1 h2", et.mirageaec.com -> localhost:8080 and
# promanage.mirageaec.com -> localhost:8081. All of it stays exactly as it is.

sudo cp -n /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak-$(date +%Y%m%d-%H%M%S)
# Keeps a dated copy of the Caddyfile before you touch it. -n: never overwrites
# an existing copy. This copy is what you restore if anything goes wrong.
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

In the DNS provider for mirageaec.com, add two **A records**, both pointing at
the VPS:

* `auth.mirageaec.com`
* `engtools.mirageaec.com`

Leave `et.mirageaec.com` and `promanage.mirageaec.com` alone.

```bash
curl -4 -s ifconfig.me; echo
# Prints the VPS's public IPv4 address: <VPS_IP>.

dig +short auth.mirageaec.com
# Must print the same address.

dig +short engtools.mirageaec.com
# Must print the same address too. If either prints nothing, wait for DNS to
# spread and try again — Caddy cannot get a certificate for a name until it does.
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

sudo ss -ltnp | grep -E ':8001\b' || echo "port 8001 is free"
# Checks again, right before Core starts, that nothing listens on 8001.
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

docker network inspect maec_core_net >/dev/null 2>&1 && echo "maec_core_net EXISTS - do not create it again" || echo "maec_core_net is absent"
# Checks first, as its own step, for the network Core and the apps share.
# Absent is what you expect on the first run.

docker network create --subnet 10.231.1.0/24 --gateway 10.231.1.1 maec_core_net
# Creates that shared network — ONCE, by hand, outside every stack, so no
# stack owns it. Skip this line if the check above said it exists.

docker network inspect maec_core_net --format '{{range .IPAM.Config}}{{.Subnet}} gateway {{.Gateway}}{{end}}'
# Must print "10.231.1.0/24 gateway 10.231.1.1". Core trusts that gateway as
# Caddy's address (TRUSTED_PROXIES); any other range and you must stop.

docker compose -f deploy/compose.yml --env-file deploy/env.production up -d --build
# Builds Core and starts it with its own PostgreSQL, joined to maec_core_net.
# It needs no app. It creates its own private network, maec_core_private.

docker compose -f deploy/compose.yml --env-file deploy/env.production ps
# Shows both containers. Wait until core reads "(healthy)" — under a minute.

docker compose -f deploy/compose.yml --env-file deploy/env.production logs core | grep -E 'Running upgrade|seed:|RuntimeError'
# Shows the migrations, the seed and any refusal. You want "seed: created ..."
# and "Global Admin is <your address>". A RuntimeError names the setting that
# is wrong; fix it and run the up command again.

curl -s http://127.0.0.1:8001/api/health; echo
# Asks Core directly. Expect "status":"ok" and "database":"ok".
```

### 3e. Caddy — add Core's block

Add this block at the end of `/etc/caddy/Caddyfile`. Change nothing else —
not the global `{ servers { protocols h1 h2 } }` block, not
`et.mirageaec.com`, not `promanage.mirageaec.com`.

```
auth.mirageaec.com {
    reverse_proxy localhost:8001
}
```

```bash
sudo cp -n /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak-$(date +%Y%m%d-%H%M%S)
# Keeps a dated copy of the Caddyfile before you touch it. -n: never overwrites
# an existing copy. This copy is what you restore if anything goes wrong.

sudo nano /etc/caddy/Caddyfile
# Opens the Caddyfile. Add the block above at the end; touch nothing else.

sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
# Checks the edited file before Caddy uses it. "Valid configuration" is what
# you want; anything else, fix it now — nothing has changed for anyone yet.

sudo systemctl reload caddy
# Makes the running Caddy load the new file in place: et.mirageaec.com and
# promanage.mirageaec.com keep serving throughout, and if the new file were
# rejected, Caddy would carry on with the old one.

sudo systemctl status caddy --no-pager | head -5
# Confirms Caddy is still "active (running)" after the reload.
```

Caddy fetches a certificate for `auth.mirageaec.com` the first time it is
asked — which is step 4.

---

## 4. Check Core on its own

In a browser, open **https://auth.mirageaec.com** and sign in as the
bootstrap admin. You land on the admin panel.

Open the developer tools → **Application** (Chrome) or **Storage** (Firefox)
→ **Cookies** → `https://auth.mirageaec.com`. The cookie `maec_one_session` must
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
docker compose -f deploy/compose.yml --env-file deploy/env.production exec core-db psql -U maec_core -d maec_identity -c "UPDATE applications SET base_url = 'https://engtools.mirageaec.com' WHERE key = 'engineering';"
# Tells Core where Engineering Tools lives. Its launcher tile opens it, and after
# sign-in people are sent back only to this exact address. Expect "UPDATE 1".
```

### 5c. Everyone who uses Engineering Tools today

The old app has **one shared password**. The new one, at
`engtools.mirageaec.com`, lets in only people with their own account *and* an
Engineering Tools seat. Make the list first — everyone who uses Engineering
Tools today — and for each person, in **Users & Access**:

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
* tell them the new address, `https://engtools.mirageaec.com`, from the day of
  step 7. The old `et.mirageaec.com`, with its shared password, keeps working
  until it is retired in step 10 — tell them that date when you set it, not
  before.

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

### 6c. Check it cannot touch what is already running

The old Engineering Tools is the Compose project `maec`, on 127.0.0.1:8080,
network `maec_maec_net`; Project Management is `promanage`, on 127.0.0.1:8081.
The new stack must differ from both, or starting it would replace or collide
with one of them.

```bash
grep -nE '^name:|127\.0\.0\.1:|ET_PORT|subnet|maec_core_net|image:' docker-compose.yml
# Shows the new stack's project name, published port, range, Core network and
# image names. You need: name "maec-et" (NOT "maec"); the port written as
# ${ET_PORT...}; its own subnet (10.231.2.0/24); maec_core_net joined as
# external; images named maec-et-…. If any is different, stop.
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
#   ET_PORT=8082                                  (the port Caddy will use)
#   CORE_URL=http://maec-core:8000                (Core, over maec_core_net)
#   CORE_PUBLIC_URL=https://auth.mirageaec.com
#   MAEC_APP_KEY=engineering
#   MAEC_GATE_SECRET=<the gate secret from 3c — the same value as Core's GATE_SECRETS>
# and everything else its README-docker.md asks for. Its entrypoint refuses to
# start on a placeholder or a short secret.
```

**Every `docker compose` command for this stack carries `--env-file .env.maec`.**
`ET_PORT` is read when Compose *reads the compose file*, and Compose takes such
values from `--env-file` (or a file named `.env`), not from the `env_file:`
the containers get. Without the flag the port falls back to the compose file's
default, 8081 — Project Management's port; Docker would refuse to start rather
than take it, but don't find out that way.

```bash
docker compose --env-file .env.maec config | grep -E 'published|host_ip'
# Prints the ports Compose WOULD publish, without starting anything. You need
# published "8082" on host_ip 127.0.0.1 — not 8081, not 80, not 8080.
```

### 6e. Start it

```bash
sudo ss -ltnp | grep -E ':8082\b' || echo "port 8082 is free"
# Checks again, right before it starts, that nothing has taken 8082.

docker compose --env-file .env.maec up -d --build
# Builds and starts the new stack on 127.0.0.1:8082, joined to maec_core_net
# (created in 3d). Core must already be running for the gate to answer.

docker compose --env-file .env.maec ps
# Wait until every container reads "(healthy)" or "Up".

docker ps --format '{{.Names}}\t{{.Ports}}' | grep -E ':(8001|8080|8081|8082)->'
# Shows all four side by side: Core on 8001, the old Engineering Tools on 8080,
# Project Management on 8081, the new Engineering Tools on 8082.
```

### 6f. Check it from the VPS shell, before anyone can reach it

This sends a request to the new stack exactly as Caddy will once
`engtools.mirageaec.com` points at it — the host it was asked for, https, and a
visitor's address:

```bash
curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  -H 'Host: engtools.mirageaec.com' -H 'X-Forwarded-Host: engtools.mirageaec.com' \
  -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-For: 203.0.113.10' \
  'http://127.0.0.1:8082/some/page?x=1'
# Asks the new Engineering Tools for a page with no session. It must answer
# with a redirect to Core's sign-in, carrying the exact page to come back to.
```

The line printed must be exactly:

```
302 https://auth.mirageaec.com/?next=https%3A%2F%2Fengtools.mirageaec.com%2Fsome%2Fpage%3Fx%3D1
```

* `503` and "MAEC One is unavailable": the new stack cannot reach Core —
  check it joined `maec_core_net` and that `CORE_URL` is `http://maec-core:8000`.
* `next=http%3A…` (plain http) or another host in `next`: the new stack is
  not reading the forwarded address correctly. Do not go live.
* No answer at all: check `docker ps` shows the new stack on 8082.

```bash
curl -s -o /dev/null -w 'old ET %{http_code}\n' http://127.0.0.1:8080/
# Confirms the old Engineering Tools still answers on 8080, untouched.

curl -s -o /dev/null -w 'ProManage %{http_code}\n' http://127.0.0.1:8081/
# Confirms Project Management still answers on 8081, untouched.
```

---

## 7. Go live — add the engtools.mirageaec.com block

Add one more block at the end of `/etc/caddy/Caddyfile`. Nothing that is
already in the file changes — `et.mirageaec.com` keeps pointing at the old
Engineering Tools on 8080.

```
engtools.mirageaec.com {
    reverse_proxy localhost:8082
}
```

```bash
sudo cp -n /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak-$(date +%Y%m%d-%H%M%S)
# Keeps a dated copy of the Caddyfile before you touch it. -n: never overwrites
# an existing copy. This copy is what you restore if anything goes wrong.

sudo nano /etc/caddy/Caddyfile
# Opens the Caddyfile. Add the block above at the end; touch nothing else.

sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
# Checks the edited file before Caddy uses it. "Valid configuration" is what
# you want; anything else, fix it now — nothing has changed for anyone yet.

sudo systemctl reload caddy
# Makes the running Caddy load the new file in place: et.mirageaec.com and
# promanage.mirageaec.com keep serving throughout, and if the new file were
# rejected, Caddy would carry on with the old one.

sudo systemctl status caddy --no-pager | head -5
# Confirms Caddy is still "active (running)" after the reload.
```

The whole Caddyfile afterwards — the first three blocks exactly as they were
this morning, two added:

```
{
    servers {
        protocols h1 h2
    }
}

et.mirageaec.com {
    reverse_proxy localhost:8080
}

promanage.mirageaec.com {
    reverse_proxy localhost:8081
}

auth.mirageaec.com {
    reverse_proxy localhost:8001
}

engtools.mirageaec.com {
    reverse_proxy localhost:8082
}
```

(If today's file writes them on one line each — `et.mirageaec.com {
reverse_proxy localhost:8080 }` — leave them as they are. Only the two new
blocks are yours.)

---

## 8. The checks

In a **fresh incognito / private window**, so no old cookie interferes. Sign
in as an ordinary person with an Engineering Tools seat — not the admin.

1. **Sign in, land back.** Open `https://engtools.mirageaec.com`: you're sent to the
   MAEC One login. Sign in, and you land back in Engineering Tools.
2. **The tool works.** A HAP PDF converts to CSV.
3. **Already signed in at MAEC One.** Open `https://auth.mirageaec.com` in a
   new tab: you're already signed in.
4. **No seat, no access.** As admin, in a *different browser*, remove the
   person's Engineering Tools seat (**Users & Access**, "Remove seat"). Refresh
   Engineering Tools: "No access". Give the seat back ("Assign seat").
5. **One sign-out.** Sign out at MAEC One. Refresh Engineering Tools: you're
   sent to the login.

All five pass: you are live. Any one fails: step 9, now.

Optional sixth, once the five pass: sign in again at `https://auth.mirageaec.com`
and click the **Engineering Tools** tile — it opens `https://engtools.mirageaec.com`
and lets you straight in.

---

## 9. Rollback — if any check in step 8 fails

```bash
sudo cp -n /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak-$(date +%Y%m%d-%H%M%S)
# Keeps a dated copy of the Caddyfile before you touch it. -n: never overwrites
# an existing copy. This copy is what you restore if anything goes wrong.

sudo nano /etc/caddy/Caddyfile
# Delete the engtools.mirageaec.com block you added in step 7. Nothing else.

sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
# Checks the edited file before Caddy uses it. "Valid configuration" is what
# you want; anything else, fix it now — nothing has changed for anyone yet.

sudo systemctl reload caddy
# Makes the running Caddy load the new file in place: et.mirageaec.com and
# promanage.mirageaec.com keep serving throughout, and if the new file were
# rejected, Caddy would carry on with the old one.

sudo systemctl status caddy --no-pager | head -5
# Confirms Caddy is still "active (running)" after the reload.
```

`engtools.mirageaec.com` stops answering; nobody was using it yet. Everyone
carries on at `et.mirageaec.com`, which never changed. Leave Core and the new
stack running, so you can find out what went wrong; put the block back when
it is fixed.

---

## 10. Later — retire et.mirageaec.com, once real users have moved

A separate step, on its own day — not part of going live. Do it only when
everyone is using `engtools.mirageaec.com` with their own account, and a week
of real use has gone well.

1. Tell everyone the old address is going, and when.
2. Point the old address at the new one, so bookmarks keep working. Back up,
   edit, validate, reload exactly as in step 7, changing only the
   `et.mirageaec.com` block, to:

   ```
   et.mirageaec.com {
       redir https://engtools.mirageaec.com{uri} permanent
   }
   ```

3. Stop the old stack, keeping its folder for a while:

   ```bash
   cd <OLD_ET_FOLDER> && docker compose down
   # Stops the old Engineering Tools and removes its containers, so 8080 is
   # free again. Its folder, code and images stay, in case you need to look back.
   ```

4. Later still: delete `<OLD_ET_FOLDER>`; remove the
   `engineeringtools.mirageaec.com` DNS record and delete the suspended Render
   service.

---

## Project Management — bring its people into Core

Core already knows Project Management: the seed registers the application
`projects` (one permission, `projects:app:use`, allowed for every built-in
role) and an uncapped subscription. It stays `coming_soon` with no address
until you make it live (the end of this section).

What the import does with each of Project Management's 61 accounts:

| In Project Management | In Core |
|---|---|
| `bu_head` (4 accounts, 2 people) | Global Admin, plus a Project Management seat |
| `engineer` (57) | Normal User / Engineer for `projects`, plus a Project Management seat |

Everyone keeps their current password: the hash is carried over and becomes
argon2id at their first sign-in to Core. The 54 engineers still on their
temporary password must change it, exactly as today.

**The CSV holds password hashes. It never leaves the server, and is shredded
at the end.**

### Export, read-only, from Project Management's database

Placeholders: `<PM_DB_SERVICE>` (its database service in the `promanage`
compose project), `<PM_DB_USER>`, `<PM_DB_NAME>`, `<PM_USERS_TABLE>`. This
assumes its database is PostgreSQL; the query only reads, in a read-only
transaction.

```bash
cd <PROMANAGE_FOLDER>
# Works from Project Management's own folder, so compose finds its project.

(umask 077 && docker compose exec -T -e PGOPTIONS='-c default_transaction_read_only=on' \
  <PM_DB_SERVICE> psql -U <PM_DB_USER> -d <PM_DB_NAME> -v ON_ERROR_STOP=1 -c "
COPY (
  WITH mapping(username, email) AS (VALUES
    ('bu.anitha', 'bu.anitha@mirageaec.com'),
    ('bu.mohan',  'bu.mohan@mirageaec.com'))
  SELECT COALESCE(m.email, u.username) AS email,
         u.full_name                  AS name,
         u.role                       AS role,
         u.password_hash              AS password_hash,
         'promanage_pbkdf2'           AS password_scheme,
         u.must_change_password       AS must_change_password
  FROM <PM_USERS_TABLE> u
  LEFT JOIN mapping m ON m.username = u.username
  WHERE u.role IN ('bu_head', 'engineer')
  ORDER BY u.id
) TO STDOUT WITH (FORMAT csv, HEADER)" > ~/pm-users.csv)
# Writes every account to ~/pm-users.csv, created readable by you only
# (umask 077). The database is opened read-only; nothing in it changes. The
# two plain usernames become their @mirageaec.com addresses through the
# two-row mapping, and nothing else is altered.

ls -l ~/pm-users.csv && wc -l ~/pm-users.csv
# Must show -rw------- and 62 lines: the header and 61 accounts.
```

### Dry run — writes nothing

```bash
cd /opt/maec-one-core
# Core's folder, for its compose file.

docker compose -f deploy/compose.yml --env-file deploy/env.production exec -T core \
  python -m backend.identity.import_users --file - < ~/pm-users.csv
# Reads the CSV from your shell into the Core container — the file itself is
# never copied in — and prints what a commit would do, by row number only.
```

Expect `summary: create 61, add role 0, add seat 0, skip 0` and a warning for
the one email outside @mirageaec.com. If it says the file is rejected, it names
the rows and why; nothing was written — fix the export, not the database.

### Commit

```bash
docker compose -f deploy/compose.yml --env-file deploy/env.production exec -T core \
  python -m backend.identity.import_users --file - --commit \
  --temp-passwords-out /tmp/pm-temp-passwords.csv < ~/pm-users.csv
# Creates the 61 accounts, their roles and seats, in one transaction: all or
# nothing. Every row carries a hash, so no temporary password should be
# needed; if any is, it goes to that file inside the container, mode 600,
# never to the screen.

docker compose -f deploy/compose.yml --env-file deploy/env.production exec -T core \
  python -m backend.identity.import_users --file - --commit \
  --temp-passwords-out /tmp/pm-temp-passwords-2.csv < ~/pm-users.csv
# Runs it again. Must print "nothing to do": the import is idempotent.
```

If the commit did write temporary passwords, copy them out, hand them over
in person, then delete both copies:

```bash
(umask 077 && docker compose -f deploy/compose.yml --env-file deploy/env.production \
  cp core:/tmp/pm-temp-passwords.csv ~/pm-temp-passwords.csv)
# Copies the file out of the container, readable by you only.

docker compose -f deploy/compose.yml --env-file deploy/env.production exec core \
  rm /tmp/pm-temp-passwords.csv
# Deletes the copy inside the container.
```

### Shred the export

```bash
shred -u ~/pm-users.csv
# Overwrites the CSV and deletes it: it held every password hash.
```

(Shred `~/pm-temp-passwords.csv` the same way once the passwords are handed out.)

### Make Project Management live in Core — at deploy time

When the gated Project Management is ready at `https://pm.mirageaec.com`:

```bash
docker compose -f deploy/compose.yml --env-file deploy/env.production exec core-db \
  psql -U maec_core -d maec_identity -c "UPDATE applications SET status = 'live', base_url = 'https://pm.mirageaec.com' WHERE key = 'projects';"
# Makes Project Management live and tells Core its address. Expect "UPDATE 1".
# The seed never undoes it.
```

Then add its gate secret to Core's `GATE_SECRETS` (`,projects=<generated as
in 3c>`) and restart Core; add the DNS A record and a Caddy block for
`pm.mirageaec.com`, as for Engineering Tools. `promanage.mirageaec.com` is not
touched.

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

`docker compose … down` on Core stops Core and its database and removes
`maec_core_private`, but **no longer removes `maec_core_net`**: that network
belongs to no stack, and the apps stay attached to it while Core is away.
`up -d` rejoins it. Remove it by hand only when no stack uses it at all:

```bash
docker network inspect maec_core_net --format '{{range .Containers}}{{.Name}} {{end}}'
# Lists the containers still attached. Remove the network only if this is empty.
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
6. **Pick its port and add a Caddy block.** Check the port is free first
   (`sudo ss -ltnp | grep -E ':<port>\b' || echo free`) — 8001, 8080, 8081
   and 8082 are taken. Publish on `127.0.0.1` only, then add
   `<app>.mirageaec.com { reverse_proxy localhost:<port> }`: back up,
   validate, reload, as in step 7.

Then give people seats on it in **Users & Access**.
