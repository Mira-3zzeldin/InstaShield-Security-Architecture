<h1 align="center">🛡️ InstaShield Wallet : Security Architecture</h1>

<p align="center">
  <code>Deploy: Production Ready</code> | <code>Stack: Flutter • Node.js • Python</code> | <code>Audit: 43 Files • 164+ Controls</code>
</p>

<hr>

<h3 align="left">🚀 What the system does</h3>
<div align="left">
&nbsp; &nbsp; &nbsp; &nbsp; InstaShield is a biometric-enabled fintech wallet: face/fingerprint auth, real-time payments over WebSocket,<br>
&nbsp; &nbsp; &nbsp; &nbsp; KYC, and a ZKTeco hardware fingerprint scanner at the kiosk. No third-party auth — the entire security layer<br>
&nbsp; &nbsp; &nbsp; &nbsp; is custom-built.
</div>

<hr>

<h3 align="left">🔑 My Role & Responsibilities</h3>
<div>
&nbsp; &nbsp; &nbsp; &nbsp; I served as the **Security Lead** and sole architect for the full-stack security layer. My responsibilities included:<br><br>
  <ul>
    <li>&nbsp; &nbsp; 🔍 Auditing every source file across seven architectural layers.</li>
    <li>&nbsp; &nbsp; 🛠️ Designing and implementing all security countermeasures.</li>
    <li>&nbsp; &nbsp; 📝 Producing the authoritative security reference and threat model documentation.</li>
  </ul>
</div>

<hr>

<details>
<summary><b>🛠️ Five Headline Controls</b></summary><br>
<div align="left">
<ul>
  <li>🔐 <b>1. No boolean trust in biometrics</b>
    <ul>
      <li>The Flutter client does not pass a matched: true flag to the server. Instead, the biometric service returns an HMAC-SHA256 proof tuple — (userId, timestamp, nonce) — signed with a shared secret that the server independently verifies. A spoofed true value from a compromised device is rejected outright.</li>
    </ul>
  </li>
<br>

  <li>👀 <b>2. All PII is blind-indexed, never plaintext-queryable</b>
    <ul>
      <li>Emails, phone numbers, and national IDs are stored AES-256-GCM encrypted. Database lookups use HMAC-SHA256 blind indexes — the same keyed-hash scheme runs identically in the Node.js backend and the Python ZK microservice, so the two systems share a search key without exchanging plaintext.</li>
    </ul>
  </li>
<br>

  <li>🔑 <b>3. Five-secret key separation across trust domains</b>
    <ul>
      <li>PII_ENCRYPTION_KEY · PII_INDEX_HMAC_KEY · JWT_SECRET · FINGERPRINT_MATCH_SECRET · FINGERPRINT_DEVICE_API_KEY — each scoped to one domain. Compromise of any single key does not cascade.</li>
    </ul>
  </li>
<br>

  <li>🌐 <b>4. WebSocket frames are wake-up signals, not authority</b>
    <ul>
      <li>Every payment outcome is re-validated over a separate certificate-pinned HTTPS call before UI updates. A spoofed frame triggers the re-check and fails.</li>
    </ul>
  </li>
<br>

  <li>💻 <b>5. Native OS hardening on every platform</b>
  <ul>
  <li><b>Android:</b> FLAG_SECURE + empty taskAffinity (StrandHogg prevention) + R8 Logcat elimination.</li>
  <li><b>iOS:</b> App Switcher privacy overlay + strict ATS.</li>
  <li><b>macOS:</b> sharingType = .none + JIT disabled + dylib injection blocked.</li>
  <li><b>Windows:</b> SetDllDirectoryW("") as first statement (CWE-427) + Dart VM flag filtering (CWE-88).</li>
  <li><b>Linux:</b> ZK service binds loopback-only; biometric templates Fernet/AES-encrypted at rest.</li>
  </ul>
<br>
</details>

<details>
<summary><b>📊 Security Metrics & Numbers</b></summary><br><br>
<table width="100%">
  <tr>
    <th>Metric</th>
    <th>Value</th>
  </tr>
  <tr>
    <td><b>📁 Source files audited</b></td>
    <td align="center">43</td>
  </tr>
  <tr>
    <td><b>🛡️ Security controls implemented</b></td>
    <td align="center">164+</td>
  </tr>
  <tr>
    <td><b>🏗️ Architectural layers covered</b></td>
    <td align="center">7</td>
  </tr>
  <tr>
    <td><b>⚠️ STRIDE threat scenarios modeled</b></td>
    <td align="center">13</td>
  </tr>
  <tr>
    <td><b>🔴 Residual critical/high risk items</b></td>
    <td align="center">0</td>
  </tr>
  <tr>
    <td><b>🟢 Residual low-risk items</b></td>
    <td align="center">23 ( All with compensating controls )</td>
  </tr>
</table>
<br>
</details>

<hr>

<h3 align="left">🤝 Connect & Collaboration</h3>
<div>
&nbsp; &nbsp; &nbsp; &nbsp; I am always looking to sync with fellow researchers, recruiters, and elite CTF teams. Whether you want to discuss<br>
&nbsp; &nbsp; &nbsp; &nbsp; full-stack security architecture, evaluate the threat models, or give feedback on my audit - I value every<br>
&nbsp; &nbsp; &nbsp; &nbsp; technical conversation! 🛡️<br><br>

&nbsp; &nbsp; &nbsp; &nbsp; 🌐 <b>Find me on :</b> <a href="https://www.linkedin.com/in/mira3zzeldin/">LinkedIn</a> | <a href="https://hashnode.com/@mira3zzeldin">Technical Blog</a> | <a href="Link">Discord</a> | <a href="https://x.com/Mira3zzeldin">Twitter</a> | <a href="mailto:mira3zzeldin@gmail.com">Gmail</a><br>
&nbsp; &nbsp; &nbsp; &nbsp; 📢 <b>Feedback :</b> Found an edge case ? Open an <a href="https://github.com/Mira-3zzeldin/InstaShield-Security-Architecture/issues/new?template=content-feedback.md">Issue</a>. Have an architectural suggestion ? Let's talk in <a href="https://github.com/Mira-3zzeldin/InstaShield-Security-Architecture/discussions">Discussions</a>.
</div>

<hr>

<h3 align="left">⚠️ Repository Disclaimer</h3>
<div>
&nbsp; &nbsp; &nbsp; &nbsp; This repository is created for architectural reference purposes only. I am committed to <b>Ethical Hacking</b>. The<br>
&nbsp; &nbsp; &nbsp; &nbsp; primary codebase remains in a secured private repository to maintain system integrity. Any unauthorized use<br>
&nbsp; &nbsp; &nbsp; &nbsp; of these techniques against systems without prior consent is strictly illegal. 
</div>

<hr>

<div align="center">
<p><b>"In the digital shadows, precision is the only difference between a researcher and a ghost."</b> 🛡️</p>
<p><small>© 2026 | InstaShield Security Architecture | by Mira-3zzeldin</small></p>
<p><b>[ 🏁 End of Session ]</b></p>
