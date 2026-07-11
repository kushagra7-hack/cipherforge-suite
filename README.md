# CipherForge - Secure Password Suite

CipherForge is a professional, security-first password management suite consisting of a 100% client-side web generator and a local-first mobile/desktop vault.

## Project Structure

This repository contains two separate projects:

- **[`cipherforge-web`](./cipherforge-web/)**: A client-side Next.js password generator featuring:
  - Cryptographically secure generation (Web Crypto API)
  - Diceware passphrases
  - Real-time Shannon Entropy analysis
  - k-Anonymity breach checking (Have I Been Pwned)
  - Zero data transmission architecture

- **[`cipherforge-mobile`](./cipherforge-mobile/)**: A Flutter local-first password manager featuring:
  - Argon2id Key Derivation
  - AES-256-GCM authenticated encryption
  - Biometric integration (`local_auth`)
  - Runtime environment shielding (screenshot blocking, root detection)
  - Clipboard auto-clear capabilities

## Quick Start

Please refer to the detailed instructions in [RUN_INSTRUCTIONS.md](./RUN_INSTRUCTIONS.md) to set up and run either application.

## Security Architecture

Both applications are built with extreme paranoia and adhere to modern security engineering principles:
1. **No `Math.random()`**: All entropy is derived from secure OS-level CSPRNGs (`crypto.getRandomValues()` and `Random.secure()`).
2. **Data Minimization**: The Next.js app sends zero telemetry and hashes passwords locally before API calls. The Flutter app zeroes master keys from memory immediately upon backgrounding.
3. **Hardened Environments**: Strict Content Security Policies (CSP) on the web, and root/jailbreak detection on mobile.

## Design System

The web application uses a custom "Dark OLED Luxury" design system with deep blacks, electric cyan accents, glassmorphic elements, and smooth micro-animations.

---
*Built with Next.js, Flutter, and uncompromising security standards.*
