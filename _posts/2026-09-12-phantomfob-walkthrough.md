---
layout: post
title: "TryHackMe — PhantomFob Walkthrough"
date: 2026-09-12
categories: [tryhackme, writeup, canbus, car-hacking]
tags: [thm, ctf, walkthrough, canbus, car-hacking, socketcand, protocol-reversing]
---

# TryHackMe — PhantomFob Walkthrough

Hello guys and welcome back to another walkthrough. This time we'll be tackling PhantomFob from TryHackMe, a car hacking challenge built around a simulated vehicle CAN bus. The target exposes a small web HMI with four fob buttons (lock, horn, arm and disarm the immobiliser), a socketcand CAN bridge and an SSH service with no credentials. The catch is that the challenge asks us to unlock the car, and the fob has no unlock button at all, so the frame has to be forged on the bus. We start by enumerating the HMI, then connect to the CAN bus on port 29536 with python-can and map the traffic. Pressing buttons reveals the fob command frame and after collecting a corpus we find it is protected by a public XOR checksum instead of any kind of secret, which means the nonce byte can be derived instead of guessed. We forge an immobiliser disarm frame to prove the construction, sweep the command byte for the magic unlock value and finally watch the door bit flip and the flag drop on the web dashboard. Let's jump in.

I began by running an nmap scan on the box using the command
```bash
nmap -sV -p- 10.49.137.191
```
The results are as follows
```
22/tcp    open  ssh        OpenSSH
8080/tcp  open  http       Werkzeug/3.1.8 Python/3.12.3
29536/tcp open  unknown
```

Port 8080 is a small web HMI for the vehicle. It has exactly four controls, LOCK, HORN, IMMOB_ARM and IMMOB_DISARM, each one posting JSON to /press
```bash
curl -s -X POST http://10.49.137.191:8080/press \
  -H "Content-Type: application/json" \
  -d '{"button":"HORN"}'
```

The dashboard also streams its state over server sent events on /events. The keys are locked, immob, horn, speed, turn, fps, seen_ids and flag. The flag field is sitting there as null which tells us exactly what the end state looks like
```bash
curl -s http://10.49.137.191:8080/events
data: {"locked": true, "immob": true, "horn": false, "speed": 20.63, "turn": 0, "fps": 277, "seen_ids": 12, "flag": null}
```
SSH is publickey only and we have no credentials so the box itself is a dead end. This challenge is meant to be solved on the wire.

Port 29536 is a socketcand CAN bridge. If you have never touched one, socketcand lets you speak raw CAN over TCP. You connect and it greets you with `< hi >`, then you open the bus with `< open can0 >` and get `< ok >`, switch it to rawmode and it streams frames as `< frame <ID> <ts> <HEXDATA> >`. Transmitting is just `< send <id> <dlc> <bytes> >`. Instead of hand rolling all of that i used python-can 4.6.1's socketcand backend in a venv which gives us a proper bus object, a decoupled notifier for receiving and a logger that writes replayable candump artifacts. The command i used to connect was
```python
import can

bus = can.Bus(interface="socketcand", host="10.49.137.191",
              port=29536, channel="can0")
```
A small census tool around that connection gives us the full bus inventory
```
[+] census 5s
  0x328   4.9/s  [door][immob][horn] A5 00 00 00 00   STATUS
  0x369  19.9/s  02 00 00 00 00 00 00 00
  0x1E2  19.9/s  08 a4 16 00 00 00 00 00
  0x5ED  96.4/s  high-rate telemetry
  0x2E8  48.1/s  telemetry
  ... 12 IDs total, 272 fps
```

Most of it is telemetry noise but two IDs matter. The status frame 0x328 updates at about 5 Hz and looks like this
```
0x328  [door][immob][horn] A5 00 00 00 00
```
So byte0 is the door, byte1 the immobiliser and byte2 the horn. The other interesting ID is 0x27E, the fob command frame, which only appears when a button is pressed. That is our target.

Pressing each of the four buttons a few times gave me a corpus of 24 fob frames. Lining them up shows a fixed shape
```
[b0] 0x13 [b2] 0x1B 0xBA [ctr] [b6] [cmd]
```
- b1 = 0x13, b3 = 0x1B and b4 = 0xBA are instance constants, identical across all four buttons
- b5 is a strict +1 counter, one increment per press with 8 bit wrap
- b7 is the command byte, stable per button

The command map for this instance is
```
LOCK         0x38
HORN         0xA6
IMMOB_ARM    0x77
IMMOB_DISARM 0x7E
```
No button emits an unlock command which is the whole point of the challenge. The three remaining bytes b0, b2 and b6 look like random noise at first glance and that is where i spent most of the engagement.

My first forgery attempts were the obvious ones. I copied a genuine frame's high entropy bytes and only changed the command. Then i tried fresh random values for all three, then all zero and all FF nonces. Every single frame was ignored. On an earlier instance of this challenge that same result led to the conclusion that the authenticator was keyed and forging was impossible but that turned out to be a methodology artifact, and i'll come back to that at the end because it is the best lesson in this box.

The breakthrough came from staring at the corpus instead of the live bus. If you XOR all eight bytes of every genuine frame together you always get the same value
```
XOR(all 8 bytes) == 0x25   (24/24 frames)
```
Which rearranges into a per frame relation between the last three unknown-ish bytes
```
b6 = b0 ^ b2 ^ ctr ^ cmd ^ 0x97
     where 0x97 = 0x13 ^ 0x1B ^ 0xBA ^ 0x25
```
That is a plain XOR checksum. There is no MAC, no key, no secret. Rearranged one more time we get the recipe
```
b0 = b6 ^ b2 ^ ctr ^ cmd ^ 0x97
```
So b0 is not random at all, it is derived from the counter. The only remaining unknowns are b2 and b6. To characterise them i wrote a rapid press probe that hammers a button several times inside a couple of seconds and tags every captured frame with its bus timestamp
```
# representative output from the bucket probe
press 0.00s  f2 13 7b 1b ba a0 86 38
press 0.45s  f3 13 7b 1b ba a1 86 38
press 0.90s  f0 13 7b 1b ba a2 86 38
press 1.55s  c0 13 3d 1b ba a3 f1 38   <- bucket changed: b2 7b->3d, b6 86->f1
```
What that shows is that b2 and b6 are per bucket constants with a bucket length of about 1.1 seconds, and they change together at the bucket boundary, while b0 tracks the counter inside the bucket and the counter itself is a strict +1. The remaining bytes b1, b3 and b4 never move at all. And the beautiful part is that b2 and b6 are observable on the bus every time a genuine frame is sent. There is nothing to predict.

The working recipe is
1. Press any button and capture the genuine frame g, which gives us the current bucket's b2 and b6 and the current counter
2. Choose ctr = g.ctr + 1 and the target command
3. Compute b0 = g.b6 ^ g.b2 ^ ctr ^ cmd ^ 0x97
4. Send [b0][0x13][g.b2][0x1B][0xBA][ctr][g.b6][cmd] immediately, inside the same bucket

The command i used to forge was
```python
def solve_b0(b2, b6, ctr, cmd):
    return (b6 ^ b2 ^ ctr ^ cmd ^ 0x97) & 0xFF
```

To prove the construction end to end i used the immobiliser as an oracle. Arm it with a genuine press so immob = 1, then forge an IMMOB_DISARM and watch the status frame
```
# representative output from run c3f4b7c36683
round 0: gap=-1322.6ms  genuine=8b13e91bba0c8e77 forged=8313e91bba0d8e7e  immob 1->0
round 1: gap=-1609.9ms  genuine=8013ef1bba0f8077 forged=9613ef1bba10807e  immob 1->0
...
[*] accepted 0/8     <- verdict counter bug: every round above flipped immob 1->0
```
The negative gap is just clock skew between our machine and the server side bus timestamps, and the accepted counter at the end is a broken heuristic in my own script. The rounds above it are what matter, every single forged DISARM flipped the immobiliser back to zero. Forging works. Now the only thing left is finding the command byte that opens the door.

An unlock sweep across the command byte space gives us the answer
```
cmd=0x15  door 1 -> 0  frame=c813261bba375b15   *** UNLOCK ***
[*] cmds that unlocked the door: ['0x15']
```

One honest correction here. My first sweep credited the unlock to command 0x19 and a burst run credited 0x17. That was detection lag, not a real result. The status frame only updates at 5 Hz while the sweep was polling faster, so the door flip was being attributed to a candidate one or two frames later than the frame that actually caused it. Re-testing properly with one candidate per run, a fresh observation, the correct counter and a 1.3 second settle window gave an unambiguous answer. 0x15 unlocks and only 0x15, while the neighbours from 0x10 to 0x14 and 0x16 to 0x1F do nothing.

And with that the vehicle reported the door opening and the dashboard handed over the flag
```bash
curl -s http://10.49.137.191:8080/events
data: {"locked": false, "immob": true, "horn": false, "speed": 99.71, "turn": 0, "fps": 276, "seen_ids": 14, "flag": "THM{C4r_H4cking_…_c00l}"}
```

Notice the immobiliser is still armed in that capture. The unlock only moves the door bit and the flag releases on the door transition, it has nothing to do with the immobiliser state.

And the box is pretty much done. No exploit framework, no shell, just reading a bus and doing some maths on the bytes. The thing i keep thinking about is how many times this challenge almost convinced me the frame was protected by a secret key. Every rejection had a mundane explanation, my early attempts copied b0 from a genuine frame while changing the counter or the command, which broke the b0 to counter relation and the checksum at the same time. The earlier instance's keyed-authenticator conclusion came from a sweep that varied only the last byte while holding everything else at genuine values, which structurally cannot find a checksum living in a different byte. The lesson i'm carrying forward is simple. When a frame is rejected, vary the field model, not just the field value. And on slow oracles like a 5 Hz status frame, confirm one candidate per run with a settle window, because a fast sweep across a lagging oracle manufactures false positives.

If you liked the walkthrough give it a clap below and follow me so that you don't miss any upcoming ones.
