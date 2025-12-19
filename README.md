# 🔐 Secure Vault (Android)

A **secure, zero-knowledge file locker** for Android built using **Flutter**, designed with a **zero-trust security model**.

> Files are encrypted locally.  
> Keys never leave the device.  
> The app cannot access your data without explicit user authentication.

---

## 🚀 Features (Current)

### ✅ Phase 1 – UI Foundation
- Lock Screen (stateless, clean UI)
- Vault Screen (UI-only empty state)
- Secure navigation flow

### ✅ Phase 2 – Lifecycle Security
- Auto-lock on app background / screen switch
- Zero-trust resume behavior
- Hardened back navigation
- Vault never exposed without unlock

### ✅ Phase 3 – Biometric Authentication + Android Keystore
- Biometric unlock (Fingerprint / Face where supported)
- Hardware-backed AES key in Android Keystore (non-exportable)
- Key usage requires user authentication

### ✅ Phase 4 – Encrypted Vault & File Handling
- Import files into a private vault directory
- Files encrypted at rest using AES-256-GCM (Android Keystore key)
- Vault listing uses a plaintext metadata-only index (`filesDir/vault/index.json`) (no crypto required)
- Decrypted file viewing uses a short-lived temp file in `cacheDir/` shared via `FileProvider` (never external storage)

---

## 🔐 Security Model (High-Level)

- **Default state:** Locked
- **Vault access:** Explicit unlock required
- **Backgrounding app:** Immediately locks
- **Resume:** Always returns to lock screen

No sensitive data is ever stored in plaintext.

---

## 🧱 Tech Stack

- **Flutter (Dart)**
- **Android (Kotlin for native security + crypto layers)**
- Material 3 (Dark theme)

---

## 🗺 Roadmap

### 🔑 Phase 3 – Authentication (Completed)

### 🗂 Phase 4 – Encrypted Vault (Completed)

### 🧨 Phase 5 – Advanced Security
- Panic mode (fake vault)
- Tamper detection (root / emulator)
- Screen capture prevention

---

## ⚠️ Disclaimer

This project is for **educational and research purposes**.  
Not yet audited for production use.

---

## 👤 Author

**Krish Natekar**  
Android · Flutter · Cybersecurity

---

## 📄 License

MIT License (to be added)

---

## 🧪 Manual Testing (Phase 4)

- **Import file → encrypted file appears in vault**
  - Unlock → Vault → `+` → pick any file
- **Verify vault directory contains only encrypted artifacts**
  - `filesDir/vault/` should contain only:
    - `*.enc` (random UUID filenames)
    - `index.json` (metadata only: filename, size, MIME type, timestamp)
- **Kill app → reopen → biometric required → files still listed**
- **Copy vault directory externally → files unreadable**
- **Disable biometrics → import/list/open fails safely**
- **Open a file → biometric prompt → file opens in external viewer (PDF/Image/etc.)**
  - Verify no plaintext is written outside `cacheDir/`
