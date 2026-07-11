<div align="center">
  <img src="https://raw.githubusercontent.com/kushagra7-hack/cipherforge-suite/master/cipherforge-web/public/globe.svg" width="100" alt="CipherForge Logo">
  <h1>🛡️ CipherForge Suite 🛡️</h1>
  <p><strong>Uncompromising Security. Beautiful Design. Zero Compromises.</strong></p>
  
  [![Next.js](https://img.shields.io/badge/Next.js-15-black?style=flat-square&logo=next.js)](https://nextjs.org/)
  [![Flutter](https://img.shields.io/badge/Flutter-3.x-02569B?style=flat-square&logo=flutter)](https://flutter.dev/)
  [![Security](https://img.shields.io/badge/Security-Strict-success?style=flat-square)](#-security-architecture)
  [![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
</div>

<br />

CipherForge is a professional, security-first password management suite consisting of a **100% client-side web generator** and a **local-first mobile/desktop vault**. Built with extreme paranoia, it features a custom "Dark OLED Luxury" design system with deep blacks, electric cyan accents, glassmorphic elements, and smooth micro-animations.

---

## 🏗️ Project Structure

This repository contains two distinct, highly-secured projects:

### 🌐 [`cipherforge-web`](./cipherforge-web/) (Next.js Password Generator)
A 100% client-side, zero-knowledge password generator.
*   **🔒 Cryptographically Secure:** Uses the Web Crypto API (`crypto.getRandomValues()`) exclusively. No `Math.random()`.
*   **🎲 Diceware Passphrases:** Generate memorable, highly secure passphrases using an EFF-inspired wordlist.
*   **📊 Real-time Entropy Analysis:** Calculates exact Shannon Entropy in bits to categorize password strength.
*   **🕵️ k-Anonymity Breach Checking:** Integrates with *Have I Been Pwned*. Hashes your password locally and only sends the first 5 characters of the SHA-1 hash over the network.
*   **🛡️ Hardened Headers:** Strict Content Security Policy (CSP), X-Frame-Options, and HSTS.

### 📱 [`cipherforge-mobile`](./cipherforge-mobile/) (Flutter Password Vault)
A local-first, encrypted vault for iOS, Android, and Desktop.
*   **🔑 Argon2id Key Derivation:** Industry-leading KDF for memory-hard key derivation.
*   **🔐 AES-256-GCM Encryption:** Authenticated encryption with randomized Initialization Vectors (IVs).
*   **👆 Biometric Integration:** Seamless login via FaceID/TouchID using `local_auth`.
*   **🛡️ Runtime Shielding:** Active defense mechanisms including screenshot blocking and root/jailbreak detection.
*   **🧹 Memory Safety:** The master key is stored as a `Uint8List` and immediately zeroed out when the app is backgrounded.

---

## 🚀 Quick Start

Ready to dive in? Check out our detailed run instructions to get the servers up and running locally.

👉 **[View the Run Instructions (RUN_INSTRUCTIONS.md)](./RUN_INSTRUCTIONS.md)**

---

## 🔒 Security Architecture Philosophy

Both applications are built from the ground up adhering to modern security engineering principles:

1.  **Zero Trust & Data Minimization:** The Next.js app sends zero telemetry and hashes passwords locally before any API calls. The Flutter app zeroes master keys from memory immediately upon backgrounding.
2.  **Strict Randomness:** All entropy is derived from secure OS-level CSPRNGs (`crypto.getRandomValues()` and `Random.secure()`). 
3.  **Fail-Fast Integrity:** Strict Content Security Policies (CSP) on the web, and environment integrity checks (root/jailbreak/debugger detection) on mobile that lock down the app if tampering is detected.

---

<div align="center">
  <i>Built with uncompromising security standards. Stay safe out there.</i>
</div>
