# Trace Logging in the Signal Protocol

This document explains the implemented trace logging system, designed to make the internal cryptographic operations of the Signal Protocol visible for learning and debugging purposes.

## 1. How to Enable/Disable Logging?

Logging is controlled via a central, static switch:

```csharp
Signal.Protocol.Demo.Logging.DebugMode.Enabled
```

-   **Enable:** Setting `DebugMode.Enabled = true;` will cause all subsequent cryptographic operations to be logged in detail to the console.
-   **Disable:** Setting `DebugMode.Enabled = false;` will stop all logging output. Logging calls in the code will then have no effect and incur no performance overhead.

This is demonstrated in `Program.cs`: The entire simulation first runs with logging enabled. Afterwards, the switch is flipped, and a final message is sent to show that the console remains silent.

## 2. How to Trace the Signal Flow Using the Logs

The logs are chronological and color-coded by category to help follow the protocol's execution.

### Log Structure:
`[Timestamp] [CATEGORY] [INSECURE DEMO ONLY – PRIVATE KEY OUTPUT] Message`

### Important Categories and their Meaning:

1.  **`[KEYGEN]` (Cyan): Key Generation**
    -   Here you can see how each device generates its identity keys (`IdentityKey`), signed pre-keys (`SignedPreKey`), and one-time pre-keys (`OneTimePreKey`).
    -   **Important:** Private and public keys are explicitly output here as Base64 strings to help trace their subsequent use.

2.  **`[X3DH]` (Magenta): X3DH/PQXDH Handshake**
    -   This section is crucial for session establishment.
    -   You will see the four Diffie-Hellman computations (`DH1` to `DH4`) from which the `IKM` (Intermediate Key Material) is composed.
    -   From the `IKM`, the final `SK` (Shared Secret) is derived using a KDF (Key Derivation Function). This `SK` becomes the first `RootKey` in the Double Ratchet.
    -   In the PQXDH demo flow, the signature verification for the PQ identity prekey is also logged here.
    -   PQ-specific traces are additionally prefixed with `INSECURE DEMO ONLY – POST-QUANTUM TRACE`.

3.  **`[RATCHET]` (Yellow): Double Ratchet (1:1 Messages)**
    -   **DH Ratchet (Asymmetric):** When a device receives a message with a new ratchet key, a DH step is performed. You will see the old `RootKey`, the DH result, and how the **new `RootKey`** and **new `ChainKey`** are derived from it.
    -   **Symmetric Ratchet (Symmetric):** With each individual message, you will see how the `MessageKey` (for encryption) and the *next* `SendingChainKey` are derived from the current `SendingChainKey`.

4.  **`[ORDERING]` (Blue): Out-of-Order Logic**
    -   Whenever a message arrives that does not have the expected counter number, it will be logged here.
    -   You will see how the protocol "fast-forwards" the chain and stores the skipped `MessageKey`s in a cache (`SkippedMessageKeys`).
    -   When a delayed message arrives, you will see how it is successfully decrypted using a key from this cache.

5.  **`[GROUP]` (Green): Sender Keys (Group Messages)**
    -   This shows the distribution of the `SenderKeyDistributionMessage` over 1:1 channels.
    -   When sending a group message, you will see the symmetric ratchet step, which is very similar to that in `[RATCHET]`, but is based on a single chain per sender.
    -   The out-of-order logic for groups is also visible here and under `[ORDERING]`.

## 3. Why are Private Keys Logged for Demo Purposes Only?

**Outputting private keys, root keys, or chain keys destroys all security of the protocol.**

-   **Private keys** are the basis of digital identity and authentication. Anyone with the private `IdentityKey` can impersonate the user.
-   **Root Keys and Chain Keys** are the fundamental secrets from which all future message keys are derived. If an attacker knows a `RootKey`, they can read all subsequent communication until the next DH ratchet occurs.

In a **PRODUCTION ENVIRONMENT**, these keys **MUST NEVER** be logged, exported, or otherwise removed from the device's protected storage.

However, for this **LEARNING PROJECT**, logging these values is invaluable. It makes the abstract KDF chains and ratchet steps tangible, demonstrating how a chain of secrets repeatedly generates new one-time keys for messages without revealing the root secret. Every log entry containing such sensitive material is therefore explicitly marked with `[INSECURE DEMO ONLY – PRIVATE KEY OUTPUT]` in red, and PQ-specific traces include `INSECURE DEMO ONLY – POST-QUANTUM TRACE`.
