# Signal Protocol: Message Ordering, Out-of-Order, and Replay Protection

This document explains the central concepts that the Signal Protocol uses to ensure asynchronous and robust communication. The accompanying C# demo implements and visualizes these mechanisms using a hybrid Double Ratchet with a post-quantum braid step.

Note: This demo is conceptually aligned with Signal but does not replicate the exact wire formats or full specification details required for interoperability with real Signal clients.

## 1. Why are Message Counters Necessary?

In an asynchronous system like the internet, there's no guarantee that messages will arrive in the order they were sent. While a TCP socket ensures this, mobile clients are often not permanently online and constantly switch networks. Signal is therefore built on stateless servers that merely receive and forward messages ("Store and Forward").

This leads to three problems that are solved by **Message Counters**:

1.  **Loss Detection (Lost Messages):** If the recipient receives message `N` and then message `N+2`, they know by the gap in the counter that message `N+1` has been lost or delayed.
2.  **Order Restoration (Ordering):** Even if messages arrive in the order 2, 1, 3, the application can sort them by their counters and display them in the correct chronological sequence.
3.  **Replay Attack Prevention:** An attacker could intercept an old message and resend it. Without a counter, the recipient might mistakenly accept this message as new. With counters, each message identifier (`Chain Key` + `Message Counter`) is accepted only once.

Each chain in the Double Ratchet (see below) and each Sender Key session in a group has its own monotonically increasing counter.

## 2. How Signal Decrypts Out-of-Order Messages

The Signal Protocol was explicitly designed to handle "out-of-order" delivery. The mechanism differs slightly between 1:1 conversations and groups.

### 2.1. Hybrid Double Ratchet (1:1 Communication)

The Double Ratchet uses two "ratchets" (ratchet mechanisms):

-   **Symmetric-key Ratchet (Chain Key):** For each message sent, a `Message Key` and the `Chain Key` for the next message are derived from a `Chain Key` (hashing). This forms a chain of keys. The counter in this chain is the **Message Number (N)**.
-   **Diffie-Hellman Ratchet (Root Key):** When a user receives a message from a partner's new DH key pair, a new `Root Key` is calculated. From this, the first `Chain Key` for a new chain is derived.

**The Out-of-Order Problem:** What happens if Alice sends messages `N` and `N+1` from Chain A, and then immediately performs a new DH ratchet (with an accompanying PQ braid step) and sends message `M` from Chain B? If Bob now receives `M` (Chain B) first and then `N` (Chain A), his ratchet has already advanced to Chain B. He can no longer access Chain A with the old state.

**The Solution: Skipped Message Keys**

-   If Bob receives a message `N+k` from the current chain, but was expecting message `N`, he skips `k` steps.
-   He derives the `Message Keys` for the skipped messages (`N` to `N+k-1`) and stores them in a **`SkippedMessageKeys` list** along with their Message Number.
-   If a delayed message (e.g., `N`) now arrives, the recipient first checks if the key exists in the `SkippedMessageKeys` list.
-   If so, the stored key is used for decryption and then removed from the list to prevent replay attacks.
-   The demo keeps only the skipped message keys for delayed messages; it does not retain entire old chain keys beyond that cache.

In our demo, this is simulated by Alice sending 3 messages, but Bob receiving them in the order 3, 1, 2. The implementation in `HybridDoubleRatchet.cs` stores the keys for messages 1 and 2 when message 3 arrives, and then uses them when the delayed messages arrive.

### 2.2. Sender Keys (Group Communication)

In groups, the Double Ratchet would be inefficient. Instead, each member (per device) sends a single message containing a **Sender Key** to all other members. This message is encrypted over the established 1:1 channels (Double Ratchet).

This `Sender Key` is the root for its own ratchet chain, similar to the `Chain Key` in 1:1 chat.

-   Each sender (`Alice-Mobile`, `Bob-Mobile`, etc.) has their own `SenderKeyState`.
-   This state contains a `Chain Key` and a **Message Counter (iteration)**.
-   When Alice sends a group message, she derives the `Message Key` for iteration `i` from her current `Chain Key` and increments the counter to `i+1`.
-   All recipients receive the message and perform the same step to update their local `SenderKeyState` copies.

**Out-of-Order in Groups:**
The logic here is identical to the Symmetric-Key Ratchet in the 1:1 case:

-   If a recipient receives a message with counter `i+k`, but was expecting `i`, they store the derived keys for iterations `i` to `i+k-1` in a local `SkippedMessageKeys` list within the `SenderKeyState`.
-   If a delayed message with counter `i` arrives, the appropriate key is retrieved from the list and used for decryption.

In the demo, we simulate this by Alice sending 5 group messages that arrive at Bob and Charlie in an unsorted order. The logic in `SenderKeyState.cs` ensures that all messages are processed correctly.

## 3. How Replay Attacks are Prevented

Replay protection is a direct result of counters and the storage of skipped keys:

1.  **Monotonically Increasing Counters:** The state is always moved forward. A message with an already used or an too old `Message Number` is discarded.
2.  **Removal from Cache:** As soon as a key from the `SkippedMessageKeys` list has been used to decrypt a delayed message, it is **immediately deleted from the list**.
3.  **Limited Storage Duration:** The number of stored "Skipped Keys" is limited (e.g., to 50 or 1000). Extremely old messages can no longer be decrypted, further minimizing the risk.

An attacker who resends message `N` fails because the recipient:
-   is either already at counter `> N` and discards the message as outdated.
-   or has already decrypted `N` as a delayed message and deleted its key. The second attempt to deliver `N` will no longer find a matching key.

## 4. Differences Between 1:1 and Group Message Ordering

| Property | 1:1 Communication (Double Ratchet) | Group Communication (Sender Keys) |
| :--- | :--- | :--- |
| **Key Source** | Shared `Root Key` calculated from DH exchange. | `Sender Key` unilaterally generated by the sender. |
| **Ratchet** | Two ratchets: DH ratchet for new chains, symmetric ratchet for messages within a chain. | Only one symmetric ratchet per sender. |
| **State** | Each device pair has a single, shared Double Ratchet state. | Each recipient stores a separate `SenderKeyState` for *each sender* in the group. |
| **Out-of-Order** | More complex, as messages from old DH chains ("epochs") also need to be handled. | Simpler, as there is only one chain per sender. |
| **Efficiency** | Inefficient for groups, as for N members, N-1 messages would have to be sent and N-1 states managed. | Very efficient. One message is sent to all, and everyone uses the appropriate `SenderKeyState` for decryption. |

In summary, Signal, through the combination of counters and the caching of keys, creates an extremely robust system that overcomes the challenges of asynchronous, unreliable mobile communication.
