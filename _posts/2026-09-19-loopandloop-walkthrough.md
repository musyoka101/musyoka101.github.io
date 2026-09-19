---
layout: post
title: "LoopAndLoop — Full Android Reverse Engineering Walkthrough"
date: 2026-09-19
categories: [android, reverse-engineering, writeup]
tags: [android, reverse-engineering, apk, jni, arm, radare2, qemu, crackme]
---

**Target:** `LoopAndLoop.apk` (`net.bluelotus.tomorrow.easyandroid`)
**Type:** Android crackme (2-layer: DEX + native ARM)
**Outcome:** Full recovery of the validation algorithm, the accepted input, and the flag — verified by executing the real compiled ARM code.
**Date:** 2026-09-19

---

## 0. TL;DR

| Item | Value |
|---|---|
| **Accepted input** | `236492408` |
| **Flag** | `alictf{Jan6N100p3r}` |
| **Gate condition** | `native_chec(input, 99) == 1835996258` |
| **Algorithm** | Mutually-recursive dispatch on `(s*2) % 3`, additive → trivially invertible |
| **Verification** | Static emulation **and** execution of the real ARM `.so` under `qemu-arm` |

---

## 1. Scope & Authorization

This is a **purpose-built reverse-engineering training target** (a crackme), not production software. It is a public training artifact, a copy of which is available at [LoopAndLoop.apk](https://github.com/kiyadesu/android-reversing-challenges/blob/master/apks/LoopAndLoop.apk). The objective is capability validation: prove that a full two-layer Android reversal — decompilation, native disassembly, algorithm reconstruction, inversion, and independent execution-based verification — is achievable with the available toolchain.

No live/production system was touched. The original artifact was never modified; all patches were applied to **copies**.

---

## 2. Target Triage

### 2.1 Hashes (chain of custody)

```
sha256 : ed9f4cdbf873eb91719ab5273ee55591b00f54cf92d40e8f78617025a99b4550
md5    : b53506eba384796c651d91913aa76d6e
size   : 1,313,577 bytes
file   : Android package (APK), with AndroidManifest.xml
```

### 2.2 Manifest / build metadata

```
package            : net.bluelotus.tomorrow.easyandroid
versionCode        : 1
versionName        : 1.0
application-label  : LoopAndLoop
targetSdkVersion   : 23   (Android 6.0)
compileSdk         : 23
launchable-activity: net.bluelotus.tomorrow.easyandroid.MainActivity
native-code        : 'armeabi'
```

### 2.3 Signing certificate

```
Signer #1 certificate DN               : CN=L, OU=H, O=M, L=L, ST=H, C=M
Signer #1 certificate SHA-256 digest   : 5713ee71373510ee9fe753c2c13f12e348a42a1f2f86b9a148977e506a569680
Signer #1 certificate SHA-1 digest     : db6ee209ca40ef84b3b17d4922163bb8e80639f4
Signer #1 certificate MD5 digest       : 09878a57ae669ab83c61f5b027696d93
```

The certificate subject is deliberately nonsense (`L, H, M...`), typical of a challenge build.

### 2.4 Archive layout (the parts that matter)

```
2643940  classes.dex
  13452  lib/armeabi/liblhm.so
```

```
lib/armeabi/liblhm.so: ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV),
                       dynamically linked, interpreter /system/bin/linker, stripped
```

**Key triage signal:** exactly one native library, `armeabi` (32-bit ARM). `targetSdk 23` means the app predates most modern hardening.

### 2.5 Native library dependencies

```
NEEDED  liblog.so  libm.so  libstdc++.so  libc.so  libdl.so
SONAME  liblhm.so
FLAGS   SYMBOLIC BIND_NOW
FLAGS_1 NOW
INIT_ARRAY    0x3eac  size 4
FINI_ARRAY    0x3ea4  size 8
```

Imported symbols (complete):

```
U abort              U memcpy             w __cxa_begin_cleanup
U __cxa_atexit       U raise              w __cxa_call_unexpected
w __cxa_type_match   U __cxa_finalize     w __gnu_Unwind_Find_exidx
U __stack_chk_fail   U __stack_chk_guard
```

Note: **no `liblog` symbols are actually used** — `liblog.so` is a link-time artifact. This matters later.

---

## 3. Attack Chain Overview

```
 ┌───────────────────────────────────────────────────────────────────┐
 │ 1. TRIAGE      identify package, ABI, native lib, entry activity   │
 ├───────────────────────────────────────────────────────────────────┤
 │ 2. DEX LAYER   jadx -> MainActivity.java: the gate + check1/2/3     │
 ├───────────────────────────────────────────────────────────────────┤
 │ 3. NATIVE      r2 -> chec() dispatch (mutual recursion, mod 3)      │
 │                r2 -> stringFromJNI2() flag builder                 │
 ├───────────────────────────────────────────────────────────────────┤
 │ 4. INVERT      additive chain => delta independent of input         │
 │                input = TARGET - delta = 236492408                   │
 ├───────────────────────────────────────────────────────────────────┤
 │ 5. DERIVE      emulate digit-mixing -> alictf{Jan6N100p3r}          │
 ├───────────────────────────────────────────────────────────────────┤
 │ 6. VERIFY      execute REAL .so under qemu-arm with stubbed JNIEnv  │
 │                chec(236492408,99) == 1835996258  ✓                  │
 │                stringFromJNI2(236492408) == "Jan6N100p3r"  ✓        │
 └───────────────────────────────────────────────────────────────────┘
```

---

## 4. Phase 1 — Java / DEX Layer

### 4.1 Decompile

```bash
jadx --no-res -d "$PWD/jadx_src" LoopAndLoop.apk
```

Result: 536 Java files. The interesting one is `MainActivity`.

> **Gotcha:** Debian's `jadx` wrapper is a shell script that `cd`s into `/usr/share/jadx/bin`, so **relative `-d` paths break** (`Can't create directory jadx_src/sources`). Always pass an absolute output path.

### 4.2 The complete validation logic

```java
package net.bluelotus.tomorrow.easyandroid;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

/* JADX INFO: loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    public native int chec(int i, int i2);

    public native String stringFromJNI2(int i);

    @Override // android.support.v7.app.AppCompatActivity, ...
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button button = (Button) findViewById(R.id.button);
        final TextView tv1 = (TextView) findViewById(R.id.textView2);
        final TextView tv2 = (TextView) findViewById(R.id.textView3);
        final EditText ed = (EditText) findViewById(R.id.editText);
        button.setOnClickListener(new View.OnClickListener() {
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                String in_str = ed.getText().toString();
                try {
                    int in_int = Integer.parseInt(in_str);
                    if (MainActivity.this.check(in_int, 99) == 1835996258) {
                        tv1.setText("The flag is:");
                        tv2.setText("alictf{" + MainActivity.this.stringFromJNI2(in_int) + "}");
                    } else {
                        tv1.setText("Not Right!");
                    }
                } catch (NumberFormatException e) {
                    tv1.setText("Not a Valid Integer number");
                }
            }
        });
    }

    @Override // android.app.Activity
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override // android.app.Activity
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public String messageMe(String text) {
        return "LoopOk" + text;
    }

    public int check(int input, int s) {
        return chec(input, s);
    }

    public int check1(int input, int s) {
        int t = input;
        for (int i = 1; i < 100; i++) {
            t += i;
        }
        return chec(t, s);
    }

    public int check2(int input, int s) {
        int t = input;
        if (s % 2 == 0) {
            for (int i = 1; i < 1000; i++) {
                t += i;
            }
            return chec(t, s);
        }
        for (int i2 = 1; i2 < 1000; i2++) {
            t -= i2;
        }
        return chec(t, s);
    }

    public int check3(int input, int s) {
        int t = input;
        for (int i = 1; i < 10000; i++) {
            t += i;
        }
        return chec(t, s);
    }

    static {
        System.loadLibrary("lhm");
    }
}
```

### 4.3 What the Java layer tells us

1. **The gate:** `check(in_int, 99) == 1835996258`. That magic constant is the target sum.
2. **`check` is a thin wrapper** around the native `chec`.
3. **`check1/check2/check3` are callbacks** — they mutate the accumulator then call *back into* `chec`. This is the "loop and loop" idea: the native side and Java side call each other.
4. **The three loops add or subtract constants** that are trivially computable:

| Method | Operation | Constant |
|---|---|---|
| `check1` | `+ Σ(1..99)` | **4950** |
| `check2` | `± Σ(1..999)` (sign depends on `s % 2`) | **499500** |
| `check3` | `+ Σ(1..9999)` | **49995000** |

5. **`stringFromJNI2(in_int)`** produces the flag body — native, so it must be reversed separately.
6. **`messageMe`** returns `"LoopOk" + text` — a decoy (never used in the gate).

### 4.4 Open question

The Java code never decides *which* of `check1/2/3` runs — that logic lives in the native `chec`. So we must reverse the dispatcher.

---

## 5. Phase 2 — Native Library Analysis

### 5.1 Recon — the library is stripped but exports JNI names

```bash
r2 -q -e scr.color=0 -c "aa; afl" lib/armeabi/liblhm.so
```

Relevant output:

```
0x00000e8c  4  120  sym.Java_net_bluelotus_tomorrow_easyandroid_MainActivity_chec
0x00000f18  3  282  sym.Java_net_bluelotus_tomorrow_easyandroid_MainActivity_stringFromJNI2
```

**This is the single biggest break in the case.** Although the binary is stripped, JNI exports must keep their names — `Java_<package>_<Class>_<method>`. That gives us named entry points instead of hunting `main`.

Embedded strings confirm the callback table:

```
0x0000229c  "net/bluelotus/tomorrow/easyandroid/MainActivity"
0x000022cc  "check1"
0x000022d3  "(II)I"
0x000022d9  "check2"
0x000022e0  "check3"
```

### 5.2 JNIEnv function-table offsets (derived from the thunks)

| JNI function | Table index | Byte offset |
|---|---|---|
| `FindClass` | 6 | `0x18` |
| `GetMethodID` | 33 | `0x84` (thunk: `+8` then `0x7c`) |
| `CallIntMethodV` | 50 | `0xc8` |
| `NewStringUTF` | 167 | `0x29c` (`0xa7 << 2`) |

The `NewStringUTF` index is the highest-value one — it tells us exactly where to intercept the flag string.

---

### 5.3 `Java_..._chec` — the dispatcher

Full listing (annotated):

```
┌ 120: sym.Java_net_bluelotus_tomorrow_easyandroid_MainActivity_chec (r0=env, r1=thiz, r2=n, r3=s)
│           0x00000e8c      f0b5           push {r4, r5, r6, r7, lr}
│           0x00000e8e      8bb0           sub sp, 0x2c
│           0x00000e90      0591           str r1, [var_14h]           ; save thiz
│           0x00000e92      0493           str r3, [var_10h]           ; save s
│           0x00000e94      1b49           ldr r1, [0x00000f04]        ; -> "net/.../MainActivity"
│           0x00000e96      0368           ldr r3, [r0]                ; r3 = *env = JNIEnv table
│           0x00000e98      041c           adds r4, r0, 0              ; r4 = env
│           0x00000e9a      7944           add r1, pc                  ; resolve string
│           0x00000e9c      9b69           ldr r3, [r3, 0x18]          ; table[6] = FindClass
│           0x00000e9e      0392           str r2, [var_ch]            ; save n
│           0x00000ea0      9847           blx r3                      ; jclass = FindClass(env, "net/.../MainActivity")
│           0x00000ea2      194e           ldr r6, [0x00000f08]        ; -> "check1"
│           0x00000ea4      194a           ldr r2, [0x00000f0c]        ; -> "(II)I"
│           0x00000ea6      071c           adds r7, r0, 0              ; r7 = jclass
│           0x00000ea8      7e44           add r6, pc
│           0x00000eaa      331c           adds r3, r6, 0
│           0x00000eac      391c           adds r1, r7, 0
│           0x00000eae      7a44           add r2, pc
│           0x00000eb0      201c           adds r0, r4, 0
│           0x00000eb2      fff7d7ff       bl GetMethodID             ; mid[0] = GetMethodID("check1","(II)I")
│           0x00000eb6      164a           ldr r2, [0x00000f10]        ; -> "(II)I"
│           0x00000eb8      331c           adds r3, r6, 0              ; r3 = "check1" + 6 = "check2"
│           0x00000eba      0790           str r0, [var_1ch]           ; table_of_mids[0] = mid0
│           0x00000ebc      391c           adds r1, r7, 0
│           0x00000ebe      7a44           add r2, pc
│           0x00000ec0      201c           adds r0, r4, 0
│           0x00000ec2      fff7cfff       bl GetMethodID             ; mid[1] = GetMethodID("check2","(II)I")
│           0x00000ec6      134a           ldr r2, [0x00000f14]        ; -> "(II)I"
│           0x00000ec8      07ad           add r5, var_1ch             ; r5 = &mid[0]
│           0x00000eca      6860           str r0, [r5, 4]             ; mid[1]
│           0x00000ecc      331c           adds r3, r6, 0
│           0x00000ece      201c           adds r0, r4, 0
│           0x00000ed0      391c           adds r1, r7, 0
│           0x00000ed2      7a44           add r2, pc
│           0x00000ed4      fff7c6ff       bl GetMethodID             ; mid[2] = GetMethodID("check3","(II)I")
│           0x00000ed8      049e           ldr r6, [var_10h]           ; r6 = s
│           0x00000eda      a860           str r0, [r5, 8]             ; mid[2]
│           0x00000edc      013e           subs r6, 1                  ; r6 = s - 1
│           0x00000ede      002e           cmp r6, 0
│       ┌─< 0x00000ee0      0ddd           ble 0xefe                   ; if (s-1 <= 0) -> return n
│       │   0x00000ee2      049b           ldr r3, [var_10h]           ; r3 = s
│       │   0x00000ee4      0321           movs r1, 3
│       │   0x00000ee6      5800           lsls r0, r3, 1              ; r0 = s * 2
│       │   0x00000ee8      00f0faf8       bl __aeabi_idivmod          ; r1 = (s*2) % 3
│       │   0x00000eec      8900           lsls r1, r1, 2              ; r1 = idx * 4
│       │   0x00000eee      4a59           ldr r2, [r1, r5]            ; r2 = mid[idx]
│       │   0x00000ef0      201c           adds r0, r4, 0              ; r0 = env
│       │   0x00000ef2      0096           str r6, [sp]                ; 2nd vararg = s-1
│       │   0x00000ef4      0599           ldr r1, [var_14h]           ; r1 = thiz
│       │   0x00000ef6      039b           ldr r3, [var_ch]            ; r3 = n
│       │   0x00000ef8      fff7baff       bl CallIntMethodV           ; thiz.mid[idx](n, s-1)
│      ┌──< 0x00000efc      00e0           b 0xf00                     ; return that
│      │└─> 0x00000efe      0398           ldr r0, [var_ch]            ; return n
│      └──> 0x00000f00      0bb0           add sp, 0x2c
└           0x00000f02      f0bd           pop {r4, r5, r6, r7, pc}
```

#### Reconstructed C

```c
int chec(JNIEnv *env, jobject thiz, int n, int s) {
    // (GetMethodID x3 for check1/check2/check3 -- done once per call)
    if (s - 1 <= 0)
        return n;                             // base case
    int idx = (s * 2) % 3;                    // dispatch selector
    return (*env)->CallIntMethod(env, thiz, mid[idx], n, s - 1);
}
```

#### Critical reading notes

1. **It is not a loop — it is mutual recursion.** The name "LoopAndLoop" refers to `chec` ↔ `check1/2/3` calling each other, not an iterative loop.
2. **The selector uses the *current* `s`, not `s-1`.** `lsls r0, r3, 1` with `r3 = [var_10h] = s` computes `(s*2) % 3`.
3. **The callback receives `s-1`** — `str r6, [sp]` stores the already-decremented `r6`. This is the recursion driver.
4. **Base case returns `n` unchanged** when `s <= 1`.
5. Because `(s*2) % 3` cycles `0,1,2,0,1,2...` as `s` decrements, `check1/2/3` are invoked in a **fixed periodic pattern** — independent of the input.

#### The three callbacks (from the Java layer)

```java
check1(input, s) -> chec(input + 4950,     s)
check2(input, s) -> chec(input ± 499500,   s)     // + if s even, - if s odd
check3(input, s) -> chec(input + 49995000, s)
```

---

### 5.4 `Java_..._stringFromJNI2` — the flag builder

Full listing (annotated):

```
┌ 282: sym.Java_net_bluelotus_tomorrow_easyandroid_MainActivity_stringFromJNI2 (r0=env, r1=thiz, r2=i)
│           0x00000f18      f0b5           push {r4, r5, r6, r7, lr}
│           0x00000f1a      464d           ldr r5, [0x00001034]        ; GOT slot
│           0x00000f1c      91b0           sub sp, 0x44
│           0x00000f1e      fa21           movs r1, 0xfa               ; 250
│           0x00000f20      7d44           add r5, pc
│           0x00000f22      2d68           ldr r5, [r5]                ; r5 = &__stack_chk_guard
│           0x00000f24      0890           str r0, [var_20h]           ; save env
│           0x00000f26      8900           lsls r1, r1, 2              ; r1 = 1000
│           0x00000f28      2b68           ldr r3, [r5]
│           0x00000f2a      101c           adds r0, r2, 0              ; r0 = i
│           0x00000f2c      161c           adds r6, r2, 0              ; r6 = i
│           0x00000f2e      0f93           str r3, [var_3ch]           ; canary
│           0x00000f30      00f088f8       bl __aeabi_idiv             ; i / 1000
│           0x00000f34      0a21           movs r1, 0xa
│           0x00000f36      00f0d3f8       bl __aeabi_idivmod          ; (i/1000) % 10
│           0x00000f3a      301c           adds r0, r6, 0
│           0x00000f3c      0491           str r1, [var_10h]           ; var_10h = a = (i/1000)%10
│           0x00000f3e      3e49           ldr r1, [0x00001038]        ; 0x2710 = 10000
│           0x00000f40      00f080f8       bl __aeabi_idiv             ; i / 10000
│           0x00000f44      0a21           movs r1, 0xa
│           0x00000f46      00f0cbf8       bl __aeabi_idivmod          ; (i/10000) % 10
│           0x00000f4a      301c           adds r0, r6, 0
│           0x00000f4c      0991           str r1, [var_24h]           ; var_24h = b = (i/10000)%10
│           0x00000f4e      0a21           movs r1, 0xa
│           0x00000f50      00f0c6f8       bl __aeabi_idivmod          ; i % 10
│           0x00000f54      0906           lsls r1, r1, 0x18
│           0x00000f56      0998           ldr r0, [var_24h]           ; r0 = b
│           0x00000f58      090e           lsrs r1, r1, 0x18           ; r1 = i%10
│           0x00000f5a      0291           str r1, [var_8h]            ; var_8h = c = i%10
│           0x00000f5c      029a           ldr r2, [var_8h]            ; r2 = c
│           0x00000f5e      0706           lsls r7, r0, 0x18
│           0x00000f60      0499           ldr r1, [var_10h]           ; r1 = a
│           0x00000f62      3f0e           lsrs r7, r7, 0x18           ; r7 = b
│           0x00000f64      131c           adds r3, r2, 0              ; r3 = c
│           0x00000f66      7b43           muls r3, r7, r3             ; r3 = b*c
│           0x00000f68      0906           lsls r1, r1, 0x18
│           0x00000f6a      090e           lsrs r1, r1, 0x18           ; r1 = a
│           0x00000f6c      0aac           add r4, var_28h             ; r4 = &buf
│           0x00000f6e      cb18           adds r3, r1, r3             ; r3 = a + b*c
│           0x00000f70      0591           str r1, [var_14h]           ; var_14h = a
│           0x00000f72      301c           adds r0, r6, 0
│           0x00000f74      3149           ldr r1, [0x0000103c]        ; 0xf4240 = 1000000
│           0x00000f76      2370           strb r3, [r4]               ; buf[0] = a + b*c
│           0x00000f78      00f064f8       bl __aeabi_idiv             ; i / 1000000
│           0x00000f7c      0a21           movs r1, 0xa
│           0x00000f7e      00f0aff8       bl __aeabi_idivmod          ; (i/1000000) % 10
│           0x00000f82      0906           lsls r1, r1, 0x18
│           0x00000f84      090e           lsrs r1, r1, 0x18
│           0x00000f86      0391           str r1, [var_ch]            ; var_ch = e = (i/1000000)%10
│           0x00000f88      4f43           muls r7, r1, r7             ; r7 = e*b
│           0x00000f8a      301c           adds r0, r6, 0
│           0x00000f8c      6421           movs r1, 0x64               ; 100
│           0x00000f8e      00f059f8       bl __aeabi_idiv             ; i / 100
│           0x00000f92      0a21           movs r1, 0xa
│           0x00000f94      00f0a4f8       bl __aeabi_idivmod          ; (i/100)%10
│           0x00000f98      0906           lsls r1, r1, 0x18
│           0x00000f9a      090e           lsrs r1, r1, 0x18
│           0x00000f9c      0a20           movs r0, 0xa               ; r0 = 10
│           0x00000f9e      031c           adds r3, r0, 0
│           0x00000fa0      4b43           muls r3, r1, r3             ; r3 = 10 * d100
│           0x00000fa2      3f06           lsls r7, r7, 0x18
│           0x00000fa4      3f0e           lsrs r7, r7, 0x18           ; r7 = e*b
│           0x00000fa6      fb18           adds r3, r7, r3             ; r3 = e*b + 10*d100
│           0x00000fa8      099a           ldr r2, [var_24h]           ; r2 = b
│           0x00000faa      0691           str r1, [var_18h]           ; var_18h = d100 = (i/100)%10
│           0x00000fac      0333           adds r3, 3                  ; r3 += 3
│           0x00000fae      0499           ldr r1, [var_10h]           ; r1 = a
│           0x00000fb0      1b06           lsls r3, r3, 0x18
│           0x00000fb2      1b0e           lsrs r3, r3, 0x18
│           0x00000fb4      0793           str r3, [var_1ch]           ; var_1ch = buf[1] value
│           0x00000fb6      6370           strb r3, [r4, 1]            ; buf[1] = e*b + 10*d100 + 3
│           0x00000fb8      8b18           adds r3, r1, r2             ; r3 = a + b
│           0x00000fba      4343           muls r3, r0, r3             ; r3 = 10*(a+b)
│           0x00000fbc      1b06           lsls r3, r3, 0x18
│           0x00000fbe      1b0e           lsrs r3, r3, 0x18
│           0x00000fc0      1f49           ldr r1, [0x00001040]        ; 0x186a0 = 100000
│           0x00000fc2      301c           adds r0, r6, 0
│           0x00000fc4      0493           str r3, [var_10h]           ; var_10h = 10*(a+b)  (overwrites a)
│           0x00000fc6      a370           strb r3, [r4, 2]            ; buf[2] = 10*(a+b)
│           0x00000fc8      e770           strb r7, [r4, 3]            ; buf[3] = e*b
│           0x00000fca      00f03bf8       bl __aeabi_idiv             ; i / 100000
│           0x00000fce      0a21           movs r1, 0xa
│           0x00000fd0      00f086f8       bl __aeabi_idivmod          ; (i/100000) % 10
│           0x00000fd4      1323           movs r3, 0x13               ; 19
│           0x00000fd6      5943           muls r1, r3, r1             ; 19 * f
│           0x00000fd8      0231           adds r1, 2                  ; + 2
│           0x00000fda      0298           ldr r0, [var_8h]            ; r0 = c
│           0x00000fdc      2171           strb r1, [r4, 4]            ; buf[4] = 19*f + 2
│           0x00000fde      0399           ldr r1, [var_ch]            ; r1 = e
│           0x00000fe0      031c           adds r3, r0, 0              ; r3 = c
│           0x00000fe2      4b43           muls r3, r1, r3             ; r3 = e*c
│           0x00000fe4      1b06           lsls r3, r3, 0x18
│           0x00000fe6      1b0e           lsrs r3, r3, 0x18
│           0x00000fe8      5a1c           adds r2, r3, 1              ; r2 = e*c + 1
│           0x00000fea      6271           strb r2, [r4, 5]            ; buf[5] = e*c + 1
│           0x00000fec      069a           ldr r2, [var_18h]           ; r2 = d100
│           0x00000fee      a371           strb r3, [r4, 6]            ; buf[6] = e*c
│           0x00000ff0      0c23           movs r3, 0xc                ; 12
│           0x00000ff2      5343           muls r3, r2, r3             ; 12 * d100
│           0x00000ff4      1b06           lsls r3, r3, 0x18
│           0x00000ff6      0498           ldr r0, [var_10h]           ; r0 = 10*(a+b)
│           0x00000ff8      0599           ldr r1, [var_14h]           ; r1 = a
│           0x00000ffa      1b0e           lsrs r3, r3, 0x18
│           0x00000ffc      e371           strb r3, [r4, 7]            ; buf[7] = 12*d100
│           0x00000ffe      0333           adds r3, 3                  ; + 3
│           0x00001000      6372           strb r3, [r4, 9]            ; buf[9] = 12*d100 + 3
│           0x00001002      079b           ldr r3, [var_1ch]           ; r3 = buf[1]
│           0x00001004      4218           adds r2, r0, r1             ; r2 = 10*(a+b) + a
│           0x00001006      2272           strb r2, [r4, 8]            ; buf[8] = 10*(a+b) + a
│           0x00001008      089a           ldr r2, [var_20h]           ; r2 = env
│           0x0000100a      283b           subs r3, 0x28               ; r3 = buf[1] - 40
│           0x0000100c      5b00           lsls r3, r3, 1              ; * 2
│           0x0000100e      1268           ldr r2, [r2]                ; r2 = JNIEnv table
│           0x00001010      a372           strb r3, [r4, 0xa]          ; buf[10] = (buf[1]-40)*2
│           0x00001012      0023           movs r3, 0
│           0x00001014      e372           strb r3, [r4, 0xb]          ; buf[11] = 0  (NUL)
│           0x00001016      a723           movs r3, 0xa7               ; 167
│           0x00001018      9b00           lsls r3, r3, 2              ; 167*4 = 668 = 0x29c
│           0x0000101a      d358           ldr r3, [r2, r3]            ; table[167] = NewStringUTF
│           0x0000101c      0898           ldr r0, [var_20h]           ; env
│           0x0000101e      211c           adds r1, r4, 0              ; buf
│           0x00001020      9847           blx r3                      ; return NewStringUTF(env, buf)
│           0x00001022      0f9a           ldr r2, [var_3ch]           ; canary check
│           0x00001024      2b68           ldr r3, [r5]
│           0x00001026      9a42           cmp r2, r3
│       ┌─< 0x00001028      01d0           beq 0x102e
│       │   0x0000102a      00f0b5ff       bl fcn.00001f98            ; __stack_chk_fail
│       └─> 0x0000102e      11b0           add sp, 0x44
└           0x00001030      f0bd           pop {r4, r5, r6, r7, pc}
```

#### Digit extraction summary

| Symbol | Expression | Meaning |
|---|---|---|
| `c` | `i % 10` | digit 0 |
| `d100` | `(i/100) % 10` | digit at 10² |
| `a` | `(i/1000) % 10` | digit at 10³ |
| `b` | `(i/10000) % 10` | digit at 10⁴ |
| `f` | `(i/100000) % 10` | digit at 10⁵ |
| `e` | `(i/1000000) % 10` | digit at 10⁶ |

#### Byte construction (the actual flag mixing)

| Offset | Expression |
|---|---|
| `buf[0]` | `a + b*c` |
| `buf[1]` | `e*b + 10*d100 + 3` |
| `buf[2]` | `10*(a+b)` |
| `buf[3]` | `e*b` |
| `buf[4]` | `19*f + 2` |
| `buf[5]` | `e*c + 1` |
| `buf[6]` | `e*c` |
| `buf[7]` | `12*d100` |
| `buf[8]` | `10*(a+b) + a` |
| `buf[9]` | `12*d100 + 3` |
| `buf[10]` | `(buf[1] - 40) * 2` |
| `buf[11]` | `0` (NUL terminator) |

Every byte is masked to 8 bits (`lsls #0x18` / `lsrs #0x18` = `& 0xFF`). The result is passed to `NewStringUTF` at JNIEnv index **167**.

---

## 6. Phase 3 — Inverting the Gate

### 6.1 The key insight

Every operation in the chain is **`+ constant` or `- constant`**. No multiplication or input-dependent branching exists. Therefore:

```
chec(input, 99) = input + DELTA
```

where `DELTA = chec(0, 99)`, a value **independent of the input**. The gate becomes:

```
input = TARGET - DELTA
```

### 6.2 Simulator

```python
M32 = 0xFFFFFFFF
def s32(x):
    x &= M32
    return x - 0x100000000 if x & 0x80000000 else x

S99, S999, S9999 = sum(range(1,100)), sum(range(1,1000)), sum(range(1,10000))
# S99 = 4950, S999 = 499500, S9999 = 49995000

dispatch = []
def chec(n, s):
    if s - 1 <= 0:
        return s32(n)
    idx = (s * 2) % 3
    dispatch.append((s, idx))
    return [check1, check2, check3][idx](n, s - 1)

def check1(inp, s): return chec(s32(inp + S99), s)
def check2(inp, s):
    t = s32(inp + S999) if s % 2 == 0 else s32(inp - S999)
    return chec(t, s)
def check3(inp, s): return chec(s32(inp + S9999), s)

TARGET = 1835996258
delta = chec(0, 99)
required_input = s32(TARGET - delta)
print(delta, required_input)          # 1599503850  236492408
print(chec(required_input, 99))       # 1835996258  -> matches TARGET
```

### 6.3 Result

```
levels executed      : 98
dispatch histogram   : {0: 66, 1: 66, 2: 64}    # idx -> count
first 6 (s, idx)     : [(99,0), (98,1), (97,2), (96,0), (95,1), (94,2)]
additive delta       : 1599503850
REQUIRED INPUT       : 236492408
verify               : chec(236492408, 99) = 1835996258  ✓
```

---

## 7. Phase 4 — Deriving the Flag

With `input = 236492408`, extract digits:

```
i        = 236492408
c        = i % 10            = 8
d100     = (i/100) % 10      = 4
a        = (i/1000) % 10     = 2
b        = (i/10000) % 10    = 9
f        = (i/100000) % 10   = 4
e        = (i/1000000) % 10  = 6
```

Apply the byte formulas:

| Offset | Formula | Value | Char |
|---|---|---|---|
| `buf[0]` | `a + b*c` = 2 + 9·8 | 74 | `J` |
| `buf[1]` | `e*b + 10*d100 + 3` = 54 + 40 + 3 | 97 | `a` |
| `buf[2]` | `10*(a+b)` = 10·11 | 110 | `n` |
| `buf[3]` | `e*b` = 54 | 54 | `6` |
| `buf[4]` | `19*f + 2` = 76 + 2 | 78 | `N` |
| `buf[5]` | `e*c + 1` = 48 + 1 | 49 | `1` |
| `buf[6]` | `e*c` = 48 | 48 | `0` |
| `buf[7]` | `12*d100` = 48 | 48 | `0` |
| `buf[8]` | `10*(a+b) + a` = 110 + 2 | 112 | `p` |
| `buf[9]` | `12*d100 + 3` = 51 | 51 | `3` |
| `buf[10]` | `(buf[1] - 40) * 2` = 57·2 | 114 | `r` |
| `buf[11]` | terminator | 0 | — |

Resulting string: **`Jan6N100p3r`**

```
FLAG = alictf{Jan6N100p3r}
```

---

## 8. Phase 5 — Independent Verification by Executing the Real Code

Static reconstruction is strong, but the flag bytes rest on my reading of the disassembly alone. To remove that dependency, the **actual compiled ARM code** was executed.

### 8.1 Obstacle 1 — the app cannot run on the emulator

```
device abilist        : x86_64, arm64-v8a
abilist32             : []            <-- NO 32-bit ABI
ro.dalvik.vm.isa.arm  : x86
```

The APK ships only `armeabi` (32-bit ARM). Install attempt:

```
adb install LoopAndLoop.apk
Failure [INSTALL_FAILED_NO_MATCHING_ABIS:
         Failed to extract native libraries, res=-113]
```

So the normal dynamic path (ARTEMIS UI driving, Frida hooking) is **unavailable for this target on this device**. This is a device/ABI constraint, not a tooling failure.

### 8.2 Obstacle 2 — Android `.so` under glibc crashes on load

Running a harness linked against `liblhm.so` gave:

```
qemu: uncaught target signal 11 (Segmentation fault)
```

Under `gdb-multiarch`, the fault was `PC = 0x00000000` — an indirect call to NULL, occurring **during library initialisation** (before `main`).

Root cause located by inspecting the init array:

```
readelf -x .init_array liblhm.so
  0x00003eac 00000000        <-- .init_array[0] == NULL
```

`DT_INIT_ARRAYSZ` = 4, and the single constructor entry is **zero**. Android's linker tolerates a null entry; glibc's `ld.so` happily calls it → jump to address 0.

Notably, `LD_DEBUG=bindings` showed **all symbols resolved correctly** (`__gnu_Unwind_Find_exidx`, `__cxa_begin_cleanup`, `__cxa_type_match`, `__stack_chk_guard`), confirming the fault was purely the null constructor.

### 8.3 Fix — patch a *copy* to neutralise the null constructor

```python
# patch_init.py — zeroes DT_INIT_ARRAYSZ / DT_FINI_ARRAYSZ on a COPY
import struct, os
SRC, DST = 'lib/armeabi/liblhm.so', 'patched/liblhm.so'
os.makedirs('patched', exist_ok=True)
data = bytearray(open(SRC, 'rb').read())
assert data[:4] == b'\x7fELF'

e_phoff     = struct.unpack_from('<I', data, 0x1c)[0]
e_phentsize = struct.unpack_from('<H', data, 0x2a)[0]
e_phnum     = struct.unpack_from('<H', data, 0x2c)[0]

dyn_off = dyn_sz = None
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    if struct.unpack_from('<I', data, o)[0] == 2:          # PT_DYNAMIC
        dyn_off = struct.unpack_from('<I', data, o + 4)[0]
        dyn_sz  = struct.unpack_from('<I', data, o + 16)[0]
        break

o, patched = dyn_off, []
while o < dyn_off + dyn_sz:
    d_tag, d_val = struct.unpack_from('<II', data, o)
    if d_tag == 0:
        break
    if d_tag in (0x1b, 0x1c):                              # INIT_ARRAYSZ / FINI_ARRAYSZ
        struct.pack_into('<I', data, o + 4, 0)
        patched.append((hex(d_tag), d_val, 0))
    o += 8

open(DST, 'wb').write(data)
print("patched:", patched)
```

Output:

```
patched: [('0x1c', 8, 0), ('0x1b', 4, 0)]
```

The **original APK and `.so` are untouched**; only `patched/liblhm.so` is modified.

### 8.4 The harness — real code, stubbed JNIEnv

`harness.c` provides a fake `JNIEnv` function table and calls the real native functions:

```c
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static char captured[512];
static void *g_env = 0;

/* real native functions, linked from liblhm.so */
extern void *Java_net_bluelotus_tomorrow_easyandroid_MainActivity_stringFromJNI2(void *env, void *thiz, int i);
extern int   Java_net_bluelotus_tomorrow_easyandroid_MainActivity_chec(void *env, void *thiz, int n, int s);

/* Java-side callbacks, reimplemented verbatim from the decompiled source */
static int c_check1(void *thiz, int input, int s);
static int c_check2(void *thiz, int input, int s);
static int c_check3(void *thiz, int input, int s);

static int call_chec(void *thiz, int n, int s) {
    return Java_net_bluelotus_tomorrow_easyandroid_MainActivity_chec(g_env, thiz, n, s);
}
static int c_check1(void *thiz, int input, int s) {
    int t = input; for (int i = 1; i < 100; i++) t += i;   return call_chec(thiz, t, s);
}
static int c_check2(void *thiz, int input, int s) {
    int t = input;
    if (s % 2 == 0) { for (int i = 1; i < 1000; i++) t += i; }
    else            { for (int i = 1; i < 1000; i++) t -= i; }
    return call_chec(thiz, t, s);
}
static int c_check3(void *thiz, int input, int s) {
    int t = input; for (int i = 1; i < 10000; i++) t += i;  return call_chec(thiz, t, s);
}

/* JNIEnv stubs, indices from the disassembly offsets */
static void *my_FindClass(void *env, const char *name) { return (void *)name; }         /* idx 6   */
static void *my_GetMethodID(void *env, void *c, const char *name, const char *sig) {    /* idx 33  */
    if (!strcmp(name, "check1")) return (void *)c_check1;
    if (!strcmp(name, "check2")) return (void *)c_check2;
    if (!strcmp(name, "check3")) return (void *)c_check3;
    return 0;
}
static int my_CallIntMethodV(void *env, void *obj, void *mid, va_list args) {           /* idx 50  */
    int a = va_arg(args, int);
    int b = va_arg(args, int);
    return ((int (*)(void *, int, int))mid)(obj, a, b);
}
static void *my_NewStringUTF(void *env, const char *utf) {                              /* idx 167 */
    strncpy(captured, utf, sizeof(captured) - 1);
    return (void *)utf;
}

int main(void) {
    void *table[256];
    memset(table, 0, sizeof(table));
    table[6]   = (void *)my_FindClass;
    table[33]  = (void *)my_GetMethodID;
    table[50]  = (void *)my_CallIntMethodV;
    table[167] = (void *)my_NewStringUTF;

    void *env_holder = (void *)table;
    g_env = (void *)&env_holder;

    const int input = 236492408;

    int r = Java_net_bluelotus_tomorrow_easyandroid_MainActivity_chec(g_env, 0, input, 99);
    printf("[1] native chec(%d, 99) = %d   target 1835996258 -> %s\n",
           input, r, (r == 1835996258) ? "MATCH" : "MISMATCH");

    captured[0] = '\0';
    Java_net_bluelotus_tomorrow_easyandroid_MainActivity_stringFromJNI2(g_env, 0, input);
    printf("[2] native stringFromJNI2(%d) = \"%s\"\n", input, captured);
    printf("\nFLAG = alictf{% raw %}{%s}{% endraw %}\n", captured);
    return 0;
}
```

**Why this is genuine verification:** `chec` is executed by the *real* library, including its real `FindClass` / `GetMethodID` / `CallIntMethodV` sequence and its real `(s*2)%3` dispatch. Only the Java-side callbacks are provided by the harness — and those are transcribed from the decompiled Java, an independent source. `stringFromJNI2` is executed **entirely** by the real library; only `NewStringUTF` is stubbed (to capture the output).

### 8.5 Build & run

```bash
# 1. stub the Android-only NEEDED lib (no symbols are actually used from it)
echo 'int __liblog_stub;' > stublog.c
arm-linux-gnueabi-gcc -shared -fPIC -o stubs/liblog.so stublog.c
ln -sf /usr/arm-linux-gnueabi/lib/libc.so.6       stubs/libc.so
ln -sf /usr/arm-linux-gnueabi/lib/libdl.so.2      stubs/libdl.so
ln -sf /usr/arm-linux-gnueabi/lib/libm.so.6       stubs/libm.so
ln -sf /usr/arm-linux-gnueabi/lib/libstdc++.so.6  stubs/libstdc++.so

# 2. build the harness
arm-linux-gnueabi-gcc -O1 -o harness harness.c lib/armeabi/liblhm.so

# 3. run against the PATCHED copy
LD_LIBRARY_PATH=patched:stubs:/usr/arm-linux-gnueabi/lib \
  qemu-arm -L /usr/arm-linux-gnueabi ./harness
```

### 8.6 Verification output

```
[1] native chec(236492408, 99) = 1835996258   target 1835996258 -> MATCH
[2] native stringFromJNI2(236492408) = "Jan6N100p3r"

FLAG = alictf{Jan6N100p3r}
```

Additionally, a minimal harness (`harness2.c`, only `NewStringUTF` stubbed) produced:

```
stringFromJNI2(236492408) = "Jan6N100p3r"
FLAG = alictf{Jan6N100p3r}
exit=0
```

**Three independent confirmations agree:**

| Method | Source of truth | Result |
|---|---|---|
| Python simulation | disassembly | `chec = 1835996258`, flag `Jan6N100p3r` |
| Real ARM `chec` under qemu | actual compiled code | `1835996258` ✓ |
| Real ARM `stringFromJNI2` under qemu | actual compiled code | `"Jan6N100p3r"` ✓ |

---

## 9. Complete Attack Chain (End-to-End Reconstruction)

A tester with only the APK can reproduce everything as follows:

1. **Triage.** Confirm package, `targetSdk 23`, single native lib `lib/armeabi/liblhm.so`, entry activity `MainActivity`.
2. **Decompile DEX** with `jadx`. Recover `MainActivity`:
   - Gate: `check(input, 99) == 1835996258`
   - Flag: `"alictf{" + stringFromJNI2(input) + "}"`
   - Callbacks `check1/2/3` add/subtract known constants.
3. **Disassemble the native lib** with `radare2`. Because it is stripped but keeps JNI exports, start directly at `Java_..._chec`.
4. **Reconstruct `chec`** as mutual recursion:
   ```
   chec(n,s) = if (s-1)<=0 then n
               else callbacks[(s*2)%3](n, s-1)
   ```
5. **Observe the chain is purely additive** → delta is input-independent.
6. **Compute** `delta = chec(0,99) = 1599503850` and therefore `input = 1835996258 - 1599503850 = 236492408`.
7. **Reconstruct `stringFromJNI2`** from the ARM digit-mixing routine → byte formulas.
8. **Evaluate** the byte formulas for `236492408` → `Jan6N100p3r`.
9. **Assemble the flag** → `alictf{Jan6N100p3r}`.
10. **Verify** by executing the real `.so` under `qemu-arm` with a stubbed `JNIEnv` (patching the null `.init_array` entry on a copy).

### Why the target is easy despite being "two layers"

| Weakness | Consequence |
|---|---|
| JNI exports retained in a stripped `.so` | Named entry points, no `main` hunt |
| Dispatch is a fixed `(s*2)%3` cycle | Entire call sequence is input-independent |
| Only add/subtract operations | Gate is linear → single subtraction to invert |
| No obfuscation, no anti-debug, no packing | Direct static read |
| Flag routine uses only integer arithmetic | Fully emulatable |

---

## 10. Reproducibility

### 10.1 Environment / toolchain

| Tool | Version | Role |
|---|---|---|
| `jadx` | 1.5.6 | DEX → Java |
| `apktool` | 3.0.3 | manifest/resources |
| `aapt2` | 2.19 (build-tools 35.0.0) | badging |
| `apksigner` | 0.9 | signature |
| `radare2` | — | ARM disassembly |
| `qemu-arm` | 11.1.0 | ARM user-mode emulation |
| `gcc-arm-linux-gnueabi` | 16.1.0 | ARM cross-compilation |
| `gdb-multiarch` | — | fault diagnosis |
| Python | 3.x | simulation |

> **`jadx` gotcha:** the Debian wrapper breaks **relative** `-d` paths (it `cd`s to `/usr/share/jadx/bin`). Always pass an absolute output directory.

### 10.2 Original commands

```bash
# triage
aapt2 dump badging LoopAndLoop.apk
apksigner verify --print-certs LoopAndLoop.apk
unzip -l LoopAndLoop.apk | grep -E 'lib/|\.dex'

# decompile
jadx --no-res -d "$PWD/jadx_src" LoopAndLoop.apk

# native recon
r2 -q -e scr.color=0 -c "aa; afl"  lib/armeabi/liblhm.so
r2 -q -e scr.color=0 -c "aa; iz"   lib/armeabi/liblhm.so
r2 -q -e scr.color=0 -c "aa; s 0xe8c; pdf" lib/armeabi/liblhm.so   # chec
r2 -q -e scr.color=0 -c "aa; s 0xf18; pdf" lib/armeabi/liblhm.so   # stringFromJNI2
```

### 10.3 Artifacts

All under the working directory:

```
jadx_src/            decompiled Java (536 files, incl. MainActivity.java)
lib/armeabi/liblhm.so  extracted native library (ORIGINAL, unmodified)
patched/liblhm.so    init-array-neutralised copy used for emulation
stubs/               liblog/libc/libdl/libm/libstdc++ shims for qemu
stublog.c            liblog stub source
sim.py               gate simulation / inversion
flag.py              stringFromJNI2 emulation
harness.c            full verification (real chec + real stringFromJNI2)
harness2.c           minimal flag-only verification
harness3.c           load-only isolation test
patch_init.py        .init_array patcher
```

Original APK: [LoopAndLoop.apk](https://github.com/kiyadesu/android-reversing-challenges/blob/master/apks/LoopAndLoop.apk) — **never modified**.

---

## 11. Limitations & Lessons

1. **Device ABI determines dynamic feasibility.** The emulator exposes only `x86_64, arm64-v8a` (`abilist32 = []`). Any `armeabi`/`armeabi-v7a`-only app cannot install or run there — which also removes ARTEMIS/Frida coverage for such targets. For ARM-only apps, use a 32-bit-capable image (`armeabi-v7a` or x86-with-translation).
2. **Android `.so` files are not directly runnable under glibc.** Beyond missing symbols, they may carry linker conventions glibc rejects — here a null `.init_array` entry. Patching a copy is a valid analysis technique; the artifact under test must be documented as modified.
3. **Retain JNI exports even when stripping.** This binary's biggest weakness is the unavoidable Java-facing symbol names.
4. **Identify algorithm *shape* before brute force.** Recognising the additive chain turned an apparent 98-level recursion into a single subtraction.
5. **Static reconstruction should be executed, not trusted.** Reading 12 byte formulas by hand has real error potential; running the genuine code eliminated it.

---

## 12. Appendix — Quick Reference

**Gate:** `chec(input, 99) == 1835996258`
**Constants:** `Σ(1..99)=4950`, `Σ(1..999)=499500`, `Σ(1..9999)=49995000`
**Delta:** `1599503850` (98 levels; dispatch histogram `{0:66, 1:66, 2:64}`)
**Input:** `236492408`
**Flag:** `alictf{Jan6N100p3r}`

**JNIEnv indices:** `FindClass=6`, `GetMethodID=33`, `CallIntMethodV=50`, `NewStringUTF=167`

**Original artifact hashes:**
```
APK sha256 : ed9f4cdbf873eb91719ab5273ee55591b00f54cf92d40e8f78617025a99b4550
APK md5    : b53506eba384796c651d91913aa76d6e
signer sha256 : 5713ee71373510ee9fe753c2c13f12e348a42a1f2f86b9a148977e506a569680
```

