## Simplified ML-KEM Braid Protocol (Demo)

This demo extends the classical Double Ratchet with a **post-quantum braid layer**.
It is **not production-ready** and is intentionally simplified for learning.

### What changes?

- Each **DH ratchet step** is paired with an **ML-KEM encapsulation**.
- The sender includes:
  - The ML-KEM ciphertext
  - A fresh PQ ratchet public key
- The receiver decapsulates the PQ secret and updates its PQ ratchet state.

### Root Key Update (Hybrid)

At every DH ratchet step:

```
RootKey = HKDF(previous_root_key || classical_dh_secret || pq_secret)
```

This preserves **hybrid security**: the session remains secure if **either**
the classical or the post-quantum layer holds.

### Logging

All PQ-related logs are marked with:

```
INSECURE DEMO ONLY – POST-QUANTUM TRACE
```

These logs can include sensitive data and are for demo visibility only.
