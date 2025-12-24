# Explanation of the X3DH Handshake

This project demonstrates the complete **Extended Triple Diffie-Hellman (X3DH)** handshake, as used in the Signal Protocol to establish a secure shared secret. The demonstration shows the process for the pairs Alice ↔ Bob, Alice ↔ Charlie, and Bob ↔ Charlie.

## Basic Principle

X3DH enables a user (the **Initiator**, e.g., Alice) to asynchronously establish a shared secret with another user (the **Recipient**, e.g., Bob). This works even if the recipient is offline, as the initiator obtains all necessary information from a "PreKey Bundle" previously uploaded by the recipient.

The process relies on four Diffie-Hellman (DH) key exchanges, whose results are combined and passed through a Key Derivation Function (HKDF) to generate the final secret. This provides strong security guarantees such as **Forward Secrecy** and **Protection against Identity Impersonation**.

## Detailed Steps by Example: Alice Initiates with Bob

### Phase 1: Setup (performed by Bob in advance)

1.  **Key Generation**: Bob locally generates his cryptographic keys:
    *   `IdentitySigningKey` (Ed25519): Long-term signing key to confirm his identity.
    *   `IdentityAgreementKey` (X25519): Long-term DH key, bound to his identity.
    *   `SignedPreKey` (X25519): Medium-term DH key, signed by the `IdentitySigningKey`.
    *   Several `OneTimePreKeys` (X25519): One-time DH keys for Forward Secrecy.
2.  **Upload**: Bob uploads the *public* parts of all these keys (`PublicIdentitySigningKey`, `PublicIdentityAgreementKey`, `PublicSignedPreKey` + signature, `PublicOneTimePreKeys`) to the `PreKeyServer`.

### Phase 2: Handshake (performed by Alice to start the session)

1.  **Bundle Retrieval**: Alice wants to communicate with Bob. She requests Bob's PreKey Bundle from the `PreKeyServer`. The server provides her with Bob's public keys, including a `OneTimePreKey` (if available).

2.  **Signature Verification**: Alice verifies the signature of Bob's `SignedPreKey`. She uses Bob's `PublicIdentitySigningKey` (which she received from the bundle) for this. This ensures that the `SignedPreKey` is authentically from Bob and has not been tampered with.

3.  **Ephemeral Key Generation**: Alice generates her own DH key pair, valid only for this session: the `EphemeralKey` (EK_A).

4.  **Diffie-Hellman Computations**: Alice now performs four DH computations to generate four separate secrets. She combines her own *private* keys with Bob's *public* keys:
    *   `DH1 = DH(IK_A, SPK_B)`: Alice's *private* `IdentityAgreementKey` & Bob's *public* `SignedPreKey`.
    *   `DH2 = DH(EK_A, IK_B)`: Alice's *private* `EphemeralKey` & Bob's *public* `IdentityAgreementKey`.
    *   `DH3 = DH(EK_A, SPK_B)`: Alice's *private* `EphemeralKey` & Bob's *public* `SignedPreKey`.
    *   `DH4 = DH(EK_A, OPK_B)`: Alice's *private* `EphemeralKey` & Bob's *public* `OneTimePreKey` (if one was in the bundle).

5.  **Final Secret Derivation (KDF)**:
    *   Alice concatenates the results of the four DH computations: `IKM = DH1 || DH2 || DH3 || DH4`.
    *   This `Input Keying Material` (IKM) is fed into a **Key Derivation Function** (HKDF-SHA256).
    *   The KDF produces the final, 32-byte `SharedSecret`. **Alice now knows the secret.**

### Phase 3: Reception (performed by Bob when he receives Alice's first message)

1.  **Receive Message**: Alice sends her first message to Bob. This message contains her public keys in the header: `PublicIdentityAgreementKey` (IK_A) and `PublicEphemeralKey` (EK_A), as well as the ID of Bob's `OneTimePreKey` she used.

2.  **Diffie-Hellman Computations**: Bob can now symmetrically calculate the same DH secrets by combining his *private* keys with Alice's *public* keys:
    *   `DH1 = DH(SPK_B, IK_A)`: Bob's *private* `SignedPreKey` & Alice's *public* `IdentityAgreementKey`.
    *   `DH2 = DH(IK_B, EK_A)`: Bob's *private* `IdentityAgreementKey` & Alice's *public* `EphemeralKey`.
    *   `DH3 = DH(SPK_B, EK_A)`: Bob's *private* `SignedPreKey` & Alice's *public* `EphemeralKey`.
    *   `DH4 = DH(OPK_B, EK_A)`: Bob's *private* `OneTimePreKey` (which he retrieves from his storage using the provided ID) & Alice's *public* `EphemeralKey`.

3.  **Final Secret Derivation (KDF)**:
    *   Bob concatenates his DH results in the exact same order: `IKM = DH1 || DH2 || DH3 || DH4`.
    *   He feeds this IKM into the same KDF (HKDF-SHA256).
    *   The result is the identical `SharedSecret`. **Bob now also knows the secret.**

Both parties, without ever exchanging their private keys, have arrived at the exact same shared secret. This `SharedSecret` can now be used as the basis for symmetric encryption of the actual messages (typically within the Double Ratchet algorithm).