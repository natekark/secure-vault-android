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
- **Android (Kotlin for native security layers – upcoming)**
- Material 3 (Dark theme)

---

## 🗺 Roadmap

### 🔑 Phase 3 – Authentication
- Biometric unlock (Fingerprint / Face)
- Android Keystore integration
- Hardware-backed AES key

### 🗂 Phase 4 – Encrypted Vault
- File import (scoped storage)
- File-level AES-GCM encryption
- Encrypted metadata

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
