<h1 align="center">🛡️ InstaShield Wallet — Security Architecture</h1>

<p align="center">
  <code>Deploy: Production Ready</code> | 
  <code>Stack: Flutter • Node.js • Python</code> | 
  <code>Audit: 43 Files • 164+ Controls</code>
</p>

---

## 🚀 What the system does

InstaShield is a biometric-enabled fintech wallet: face/fingerprint auth, real-time payments over WebSocket, KYC, and a ZKTeco hardware fingerprint scanner at the kiosk. No third-party auth — the entire security layer is custom-built.

---

## 🔑 My Role & Responsibilities

I served as the **Security Lead** and sole architect for the full-stack security layer. My responsibilities included:
* 🔍 Auditing every source file across seven architectural layers.
* 🛠️ Designing and implementing all security countermeasures.
* 📝 Producing the authoritative security reference and threat model documentation.

---

## 🛠️ Five Headline Controls

<details>
<summary><b>1 — No boolean trust in biometrics</b> 🔐</summary>
<br>
The Flutter client does not pass a <code>matched: true</code> flag to the server. Instead, the biometric service returns an HMAC-SHA256 proof tuple — <code>(userId, timestamp, nonce)</code> — signed with a shared secret that the server independently verifies. A spoofed <code>true</code> value from a compromised device is rejected outright.
</details>

<details>
<summary><b>2 — All PII is blind-indexed, never plaintext-queryable</b> 👁️</summary>
<br>
Emails, phone numbers, and national IDs are stored AES-256-GCM encrypted. Database lookups use HMAC-SHA256 blind indexes — the same keyed-hash scheme runs identically in the Node.js backend and the Python ZK microservice, so the two systems share a search key without exchanging plaintext.
</details>

<details>
<summary><b>3 — Five-secret key separation across trust domains</b> 🔑</summary>
<br>
<code>PII_ENCRYPTION_KEY</code> · <code>PII_INDEX_HMAC_KEY</code> · <code>JWT_SECRET</code> · <code>FINGERPRINT_MATCH_SECRET</code> · <code>FINGERPRINT_DEVICE_API_KEY</code> — each scoped to one domain. Compromise of any single key does not cascade.
</details>

<details>
<summary><b>4 — WebSocket frames are wake-up signals, not authority</b> 🌐</summary>
<br>
Every payment outcome is re-validated over a separate certificate-pinned HTTPS call before UI updates. A spoofed frame triggers the re-check and fails.
</details>

<details>
<summary><b>5 — Native OS hardening on every platform</b> 💻</summary>
<br>
<ul>
  <li><b>Android:</b> <code>FLAG_SECURE</code> + empty <code>taskAffinity</code> (StrandHogg prevention) + R8 Logcat elimination.</li>
  <li><b>iOS:</b> App Switcher privacy overlay + strict ATS.</li>
  <li><b>macOS:</b> <code>sharingType = .none</code> + JIT disabled + dylib injection blocked.</li>
  <li><b>Windows:</b> <code>SetDllDirectoryW("")</code> as first statement (CWE-427) + Dart VM flag filtering (CWE-88).</li>
  <li><b>Linux:</b> ZK service binds loopback-only; biometric templates Fernet/AES-encrypted at rest.</li>
</ul>
</details>

---

## 📊 Security Metrics & Numbers

| Metric | Value |
|---|---|
| 📁 Source files audited | 43 |
| 🛡️ Security controls implemented | 164+ |
| 🏗️ Architectural layers covered | 7 |
| ⚠️ STRIDE threat scenarios modeled | 13 |
| 🔴 Residual critical/high risk items | **0** |
| 🟢 Residual low-risk items | 23 (all with compensating controls) |

---

## 🤝 Connect & Collaboration

I am always looking to sync with fellow researchers, recruiters, and elite teams. Feel free to connect or review the full documentation!

* 📂 **Full Security Reference:** View the deep-dive audit at [`docs/SECURITY_DOCUMENTATION_PUBLIC.md`](./docs/SECURITY_DOCUMENTATION_PUBLIC.md)
* 💼 **Find me on:** [LinkedIn](حطي_رابط_لينكد_إن_بتاعك)

---
<p align="center">© 2026 | InstaShield Security Architecture Portfolio | by Mira-3zzeldin</p>
