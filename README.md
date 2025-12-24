# Signal Protocol Demo: A Didactic, Insecure-by-Design Implementation

## Project Overview

This project is a didactic (educational) demo implementation of core components of the Signal Protocol, written in C# (.NET Core 10). Its primary purpose is to illustrate the complex cryptographic mechanisms and messaging flows that underpin modern secure communication.

The demo provides a step-by-step trace of key agreement, message encryption/decryption, and advanced features like out-of-order message handling and group messaging. It simulates multiple users and devices communicating entirely in-memory, without any actual network communication or persistence.

**WARNING: This project is designed purely for demonstration and educational purposes. It is explicitly NOT production-ready and contains features (e.g., plaintext logging of private keys) that would compromise security in a real-world application.**

## Implemented Signal Components

This demo showcases the following Signal Protocol components and concepts:

*   **Identity Keys, Signed PreKeys, One-Time PreKeys**: Illustrates the generation and role of these foundational keys in establishing trust and initial key agreement.
*   **PreKey Server (Simulated)**: A simplified in-memory simulation of a server that stores and serves public PreKey Bundles.
*   **X3DH Key Agreement**: Demonstrates the Extended Triple Diffie-Hellman handshake for establishing a secure shared secret between two parties, even if one is offline.
*   **Double Ratchet (1:1 Messaging)**: Implements the Double Ratchet algorithm for forward secrecy and future secrecy in one-to-one conversations. This includes both the DH ratchet and the symmetric-key ratchet.
*   **Signal Group Messaging (Sender Keys)**: Shows how group messages are securely exchanged using Sender Keys, enabling efficient encryption for multiple recipients.
*   **Multi-Device Support**: Users can have multiple devices (e.g., Mobile, Desktop, Tablet), and the demo illustrates how sessions and keys are managed across them.
*   **Message Ordering & Out-of-Order Handling**: Explains and demonstrates how the protocol gracefully handles messages that arrive out of their intended sequence.
*   **Skipped Message Keys**: Implementation of the mechanism to temporarily store message keys for out-of-order messages, allowing for their eventual decryption.
*   **Replay Protection**: Shows how message counters and key expiration prevent replay attacks.
*   **Debug & Trace Logging**: A custom logging system that provides granular, step-by-step insights into cryptographic operations.

## Architecture Overview

The project follows a clear separation of concerns, simulating different layers of a secure messaging application:

```
+----------------+       +-------------------+       +-------------------+
|      User      |<----->|      Device       |<----->|     KeyManager    |
+----------------+       +-------------------+       +-------------------+
        ^                        |                               |
        |                        | (Owns multiple devices)       | (Manages keys for one device)
        |                        V                               V
+----------------+       +-------------------+           +-------------------+
|   MessageService  |<----->| TransportService  |<----->|   PreKeyServer    |
|(1:1 sessions/DR) |       |(Message Queue)    |       |(Public Key Bundles)|
+----------------+       +-------------------+           +-------------------+
        ^                        |
        |                        |
        |                        V
+---------------------+  +---------------------+
| GroupMessageService |<->|    GroupSession     |
|(Sender Keys)        |  |(Group Metadata)     |
+---------------------+  +---------------------+
```

**Major Classes and Responsibilities:**

*   **`User`**: Represents a user with a name and a collection of `Device` instances.
*   **`Device`**: Represents a single device belonging to a user. It manages its `KeyManager` and stores `DoubleRatchet` sessions (`PairwiseSessions`) and `SenderKeyState` instances (`ReceivedSenderKeyStates`, `OwnSenderKeyStates`).
*   **`KeyManager`**: Handles the generation and management of X3DH-related keys (Identity, Signed PreKey, One-Time PreKeys) for a single `Device`.
*   **`PreKeyServer`**: A simulated server that stores and provides public PreKey Bundles to initiating devices.
*   **`MessageService`**: Manages 1:1 Double Ratchet sessions, initiates X3DH handshakes, and handles the encryption/decryption of 1:1 messages. It interacts with the `TransportService`.
*   **`GroupMessageService`**: Manages group sessions, handles the distribution of Sender Keys, and encrypts/decrypts group messages using Sender Keys. It uses the `MessageService` for 1:1 key distribution.
*   **`TransportService`**: A simulated network layer that queues messages and delivers them. Crucially, it allows for out-of-order message delivery to demonstrate the protocol's robustness.
*   **`DoubleRatchet`**: Implements the state and logic for a single Double Ratchet session, including key derivation for message encryption and decryption, and handling of skipped message keys.
*   **`SenderKeyState`**: Manages the cryptographic state for a sender within a group, including its Chain Key, Message Counter, and Skipped Message Keys.
*   **`KDFUtil`**: Utility class providing Key Derivation Functions (KDFs) and Diffie-Hellman (DH) operations.
*   **`TraceLogger`**: A custom static logger for detailed, categorized, and color-coded trace output.
*   **`DebugMode`**: A global static switch to enable or disable detailed trace logging at runtime.

**Separation of Concerns:**
The architecture clearly separates cryptographic logic (handled by `KeyManager`, `X3DHSession`, `DoubleRatchet`, `SenderKeyState`, `KDFUtil`) from application-level messaging (orchestrated by `MessageService`, `GroupMessageService`) and simulated transport (`TransportService`). Logging is also a distinct concern, managed by `TraceLogger` and `DebugMode`.

## Message Flow Summary

### 1:1 Messaging Flow (Alice ↔ Bob)

1.  **Bob's Setup**: Bob generates his Identity Keys, Signed PreKey, and One-Time PreKeys, then uploads their public parts to the `PreKeyServer`.
2.  **Alice Initiates**: Alice wants to send a message to Bob.
    *   She fetches Bob's public PreKey Bundle from the `PreKeyServer`.
    *   She performs the **X3DH handshake** with Bob's public keys and her own private keys to derive a shared secret.
    *   A `DoubleRatchet` session is initialized for Alice using this shared secret.
    *   Alice encrypts her first message using her `DoubleRatchet` session.
3.  **Bob Receives**: Bob receives Alice's first message (which contains Alice's public keys).
    *   He performs the **X3DH handshake** symmetrically with Alice's public keys and his own private keys to derive the *same* shared secret.
    *   A `DoubleRatchet` session is initialized for Bob using this shared secret.
    *   Bob decrypts Alice's message using his `DoubleRatchet` session.
4.  **Ongoing Communication**: Subsequent messages between Alice and Bob use their established `DoubleRatchet` sessions, advancing the symmetric and DH ratchets for forward and future secrecy.

### Group Messaging Flow Using Sender Keys

1.  **Group Creation**: A user (e.g., Alice's Mobile) creates a group and becomes the initial Sender Key distributor for that group.
2.  **Sender Key Distribution**:
    *   Alice's Mobile generates a `SenderKeyState` (containing a signing key and a chain key) for the group.
    *   She then creates a `SenderKeyDistributionMessage` (containing the public signing key and initial chain key).
    *   This distribution message is sent, encrypted via the established 1:1 `DoubleRatchet` sessions, to all other devices in the group.
3.  **Recipient Processing**: Each recipient device (e.g., Bob's Mobile, Charlie's Tablet) receives the `SenderKeyDistributionMessage` via their 1:1 session. They store the public signing key and initial chain key as a `ReceivedSenderKeyState` for that sender within the group.
4.  **Group Message Sending**:
    *   When Alice's Mobile sends a group message, her `SenderKeyState` advances its symmetric ratchet, deriving a `MessageKey` for encryption and a new `ChainKey`.
    *   The message is encrypted with the `MessageKey` and signed with her `SenderKeyState`'s private signing key.
    *   The encrypted and signed message is then queued by the `TransportService` for all group members.
5.  **Group Message Receiving**:
    *   Recipient devices receive the group message.
    *   They use the stored `ReceivedSenderKeyState` for Alice's Mobile to verify the signature (using her public signing key) and decrypt the message (by advancing their local `ReceivedSenderKeyState`'s symmetric ratchet to derive the correct `MessageKey`).

### Multi-Device Message Delivery

The demo implicitly supports multi-device delivery through the `TransportService`. When a message (1:1 or group) is intended for a user with multiple devices, the `TransportService` ensures that all relevant devices receive a copy of the message. Each device then processes the message using its own independent sessions and keys. The demo focuses on the cryptographic processing rather than the exact transport mechanism to each individual device.

## Debug & Trace Logging

A detailed logging system (`TraceLogger`) is central to understanding the protocol's mechanics in this demo.

### How to Enable/Disable Debug Logging

The logging is controlled by a static boolean switch:

```csharp
Signal.Protocol.Demo.Logging.DebugMode.Enabled = true;  // Enable detailed logging
Signal.Protocol.Demo.Logging.DebugMode.Enabled = false; // Disable logging
```

In `Program.cs`, the demo runs in two phases: first with debug logging **enabled** (showing all cryptographic steps), then with it **disabled** (showing reduced, high-level output).

### What is Logged

The `TraceLogger` categorizes logs for clarity:

*   `[KEYGEN]`: Key generation (Identity, PreKeys, One-Time PreKeys).
*   `[X3DH]`: X3DH handshake steps, DH computations, IKM derivation, Shared Secret.
*   `[RATCHET]`: Double Ratchet advancements (DH ratchet, symmetric ratchet), Root Key, Chain Key, Message Key derivation.
*   `[GROUP]`: Sender Key distribution, group message sending/receiving, signature verification.
*   `[ORDERING]`: Handling of out-of-order messages, skipped message keys, chain fast-forwarding.
*   `[INFO]`: General flow and high-level events.

### Why Private Keys are Logged (Demo-Only)

**WARNING: In a real-world, secure messaging application, logging private keys or derived session keys would be an catastrophic security flaw.**

For didactic purposes, this demo **intentionally logs sensitive cryptographic material**, including private keys, Root Keys, and Chain Keys. This is done to provide full transparency into the key derivation process and to allow students and security engineers to:

*   Observe the values of intermediate and final keys.
*   Understand how keys are transformed and derived from one step to the next.
*   Verify the mathematical operations (e.g., DH computations, HKDF outputs) being performed.

Each log entry containing such sensitive data is explicitly prefixed with: `[INSECURE DEMO ONLY – PRIVATE KEY OUTPUT]` to underscore its highly insecure nature in any context outside of this specific learning environment.

## Out-of-Order & Message Ordering

The Signal Protocol is designed to handle message delivery in an unreliable, asynchronous environment where messages can be delayed, duplicated, or arrive out of sequence.

*   **Message Counters (N)**: Each message within a symmetric key chain (both in Double Ratchet and Sender Keys) carries a monotonically increasing message number. This allows recipients to detect missing messages and order correctly.
*   **Previous Message Number (PN)**: In the Double Ratchet, a message also carries the number of messages sent in the sender's *previous* sending chain. This is crucial for synchronizing ratchets and informing the recipient how many keys to "skip" from their receiving chain.
*   **Skipped Message Key Handling**:
    *   If a recipient expects message `N` but receives message `N+k`, they will "fast-forward" their receiving chain `k` times.
    *   During this fast-forward, all `MessageKey`s for `N` through `N+k-1` are derived and stored in a temporary `SkippedMessageKeys` cache.
    *   If the original message `N` (or any other skipped message) later arrives, its corresponding key is retrieved from this cache for decryption and then immediately removed to prevent replay attacks.
*   **Replay Protection**: The combination of unique message counters and the "use-once-then-discard" nature of `SkippedMessageKeys` ensures that an attacker cannot simply re-send an old message to trick the recipient.

## Limitations & Security Disclaimer

This demo project has several intentional limitations and should **NEVER** be used in a production environment:

*   **No Persistence**: All user, device, and session data exists only in memory and is lost when the program terminates.
*   **No Network Layer**: Communication between devices is simulated in-memory via the `TransportService` message queue, not over an actual network.
*   **Insecure Demo Logging**: As described above, sensitive cryptographic material is logged in plaintext for educational purposes. This is a critical security vulnerability in any real application.
*   **Simplified Cryptography**: While using the `NSec.Cryptography` library for robust primitives, the overall implementation simplifies certain aspects of the Signal Protocol for clarity (e.g., no session expiration, no session trimming, basic key management for one-time prekeys).
*   **Not Suitable for Production**: Due to the above, this code is not engineered for security, reliability, or performance required in a production system.

## How to Run the Demo

### Prerequisites

*   **.NET Core SDK 10** (or compatible version) installed.

### How to Build

Navigate to the project's root directory (where `Signal.Protocol.Demo.sln` is located) and run:

```bash
dotnet build
```

### How to Run

After building, navigate to the `Signal.Protocol.Demo` subdirectory and run:

```bash
dotnet run
```

Alternatively, from the solution root:

```bash
dotnet run --project Signal.Protocol.Demo/Signal.Protocol.Demo.csproj
```

### What Output to Expect

The console output will be entirely in English. You will first see a detailed trace of all cryptographic operations with debug logging **enabled**. This includes key generation, X3DH handshakes, Double Ratchet advancements, and group messaging flows, with sensitive key material explicitly marked.

Following the detailed phase, debug logging will be **disabled**, and a final set of messages will be sent. During this phase, you should observe significantly reduced output, demonstrating that the `TraceLogger` effectively becomes silent when `DebugMode.Enabled` is `false`.

## Terminology

A short glossary of Signal-specific terms used in this project:

*   **Identity Key (IK)**: A long-term key pair that defines a user's identity.
*   **Signed PreKey (SPK)**: A medium-term key pair, signed by the Identity Key, used in X3DH.
*   **One-Time PreKey (OPK)**: A ephemeral key pair, used only once, to provide additional forward secrecy in X3DH.
*   **PreKey Bundle**: A collection of public keys (IK, SPK, OPK) uploaded to a server by a recipient.
*   **X3DH (Extended Triple Diffie-Hellman)**: A key agreement protocol used to establish a shared secret between two parties.
*   **Ephemeral Key (EK)**: A short-lived, session-specific key pair generated by the initiator in X3DH.
*   **Shared Secret (SK)**: The symmetric key derived from the X3DH handshake, used to seed the Double Ratchet.
*   **Double Ratchet**: An algorithm that continuously updates session keys after every message, providing forward and future secrecy.
*   **Root Key (RK)**: A key in the Double Ratchet used to derive Chain Keys and subsequent Root Keys.
*   **Chain Key (CK)**: A key in the Double Ratchet used to derive Message Keys and the next Chain Key.
*   **Message Key (MK)**: A symmetric key derived from the Chain Key, used for encrypting and decrypting a single message.
*   **Sender Key**: A symmetric key used as the root for a chain of message keys in Signal's group messaging, analogous to a Chain Key for a group sender.
*   **SenderKeyState**: The cryptographic state for a specific sender within a group.
*   **Message Counter**: A monotonically increasing number associated with each message, used for ordering and replay protection.
*   **Skipped Message Keys**: A cache for message keys that were derived but not immediately used, typically due to out-of-order message arrival.
*   **Forward Secrecy**: A property ensuring that compromise of long-term keys does not compromise past session keys.
*   **Future Secrecy**: A property ensuring that compromise of past session keys does not compromise future session keys.
*   **Out-of-Order Message**: A message that arrives at the recipient out of its expected sequence.
