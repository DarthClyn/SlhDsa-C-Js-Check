
# Qinfi SLH-DSA Signing Pipeline (CLI + Native)

## Overview

This project implements a **post-quantum SLH-DSA signing pipeline** for Quranium (QL1EVM), designed to work across:

* **Windows (PowerShell, Node.js CLI)**
* **WSL / Linux (C reference signer)**
* **Android (planned via JNI + NDK)**

The goal is to ensure **cryptographic equivalence** between:

* Noble (JavaScript) SLH-DSA signing
* Reference C SLH-DSA signing
* Future Android native signing

All signing is done over a **transaction message hash**, not raw transactions.

---

## Architecture Summary

```
┌──────────────┐
│ Node.js CLI  │
│ (Windows)    │
└─────┬────────┘
                  │
                  │ Step 1: Create tx + msgHash
                  ▼
┌──────────────────┐
│ trxn.json        │
│ - txData         │
│ - unsigned RLP   │
│ - msgHash (32B)  │
└─────┬────────────┘
                  │
                  │ Step 2: Sign
                  │  - JS (Noble) OR
                  │  - C signer (WSL)
                  ▼
┌──────────────────┐
│ sign.json        │
│ - signature      │
│ - public key     │
└─────┬────────────┘
                  │
                  │ Step 3: Broadcast
                  ▼
┌──────────────────┐
│ Quranium RPC     │
└──────────────────┘
```

---

## Design Principles

* **Separation of concerns**

      * Transaction construction
      * Signing
      * Broadcasting
* **Stateless signing**

      * Signer only receives `msgHash`
* **No filesystem usage in production**

      * CLI uses files for debugging only
* **Interoperability**

      * JS and C signers are interchangeable
* **Future Android support**

      * C signer written to be reused via JNI

---

## Node.js CLI (Windows / PowerShell)

### Purpose

* Create transactions
* Generate canonical RLP
* Compute `msgHash`
* Broadcast signed transactions

### Steps

#### 1️⃣ Create transaction

```text
1. Create transaction
```

Creates `trxn.json` containing:

* `txData`
* `unsignedRlpHex`
* `msgHash` (Keccak-256 hash)

#### 2️⃣ Sign transaction

```text
2. Sign transaction
```

Signs `msgHash` using:

* Noble SLH-DSA (JavaScript)

Outputs `sign.json`.

#### 3️⃣ Broadcast transaction

```text
3. Broadcast transaction
```

Broadcasts the signed transaction to Quranium RPC.

---

## C Signer (WSL / Linux)

### Purpose

* Prove that **reference C SLH-DSA signing** produces valid signatures
* Validate interoperability with Noble
* Prepare codebase for Android NDK reuse

### Location

```
cgit/C/trxn.c
```

### Behavior

* Reads `msgHash` from project-root `trxn.json`
* Signs the hash using SLH-DSA (C implementation)
* Outputs `sign.json` in project root
* Does **not**:

      * Parse transactions
      * Perform RLP
      * Access RPC
      * Store keys permanently

### Build (from `cgit/C`)

```bash
make trxn
```

### Run

```bash
./trxn
```

After running, `sign.json` will be created in the project root and can be broadcast using the Node.js CLI.

---

## Why `msgHash` Signing?

Instead of signing raw transactions:

* Ensures **exact byte equivalence** across languages
* Avoids RLP edge cases in multiple runtimes
* Matches EVM-style signing semantics
* Makes the signer reusable across:

      * CLI
      * Mobile
      * Hardware
      * Secure enclaves

---

## Current Status

* ✅ Noble (JS) signing — **working**
* ✅ C (WSL) signing — **working**
* ✅ Transactions broadcast successfully
* ✅ JS ↔ C cryptographic equivalence proven

---

## Next Phase: Android Native Signer (Planned)

### Goal

Integrate the **same C signer** into the Qinfi Android app without changing the transaction pipeline.

---

## Planned Android Bridge (To-Do)

### High-level approach

```
React Native JS
             ↓
Kotlin Native Module
             ↓ JNI
C SLH-DSA Signer
```

### Key points

* Private keys remain in **Android secure storage**
* Keys are extracted **only in Kotlin**
* C code receives:

      * `msgHash` (32 bytes)
      * `privateKey` (in-memory)
* C code:

      * Signs blindly
      * Returns signature bytes
      * Zeroes sensitive memory
* React Native:

      * Receives signature
      * Broadcasts as usual

---

## Android Bridge – To-Dos

### C Layer

* Refactor signer into:

      ```c
      int slh_sign_msghash(
            const uint8_t *msgHash32,
            const uint8_t *privateKey,
            uint8_t *outSig,
            size_t *outSigLen
      );
      ```
* Remove all file I/O
* Stateless, deterministic interface

### JNI Layer

* Expose C signer via JNI
* Handle byte arrays only
* Zero sensitive buffers after use

### Kotlin Layer

* Fetch private key from secure storage
* Call native signer
* Return signature to React Native

### React Native

* Feature-flag native signer
* Keep Noble as fallback initially

---

## Security Notes

* Private keys never touch disk
* Private keys never touch JavaScript
* Signing is isolated to native memory
* Same trust model as current Noble setup
* Future-ready for HSM / TEE integration

---

## Conclusion

This project establishes a **clean, portable, and secure SLH-DSA signing pipeline** that works today on:

* Windows (Node.js CLI)
* WSL (C reference signer)

…and is architected to be reused directly inside an Android React Native application using JNI + NDK.

---