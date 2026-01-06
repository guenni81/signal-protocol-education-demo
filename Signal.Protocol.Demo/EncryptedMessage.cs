using NSec.Cryptography;

namespace Signal.Protocol.Demo;

/// <summary>
/// Represents an encrypted message exchanged between users.
/// Contains the header and the ciphertext.
/// </summary>
public class EncryptedMessage
{
    /// <summary>
    /// The sender's public ratchet key for this message.
    /// </summary>
    public PublicKey SenderRatchetKey { get; }
    
    /// <summary>
    /// The message number in the current chain.
    /// </summary>
    public uint MessageNumber { get; }
    
    /// <summary>
    /// The number of messages in the previous sending chain.
    /// </summary>
    public uint PreviousMessageNumber { get; }

    /// <summary>
    /// The ciphertext of the message.
    /// </summary>
    public byte[] Ciphertext { get; }

    /// <summary>
    /// Optional ML-KEM ciphertext for the PQ ratchet step.
    /// </summary>
    public byte[]? PostQuantumCiphertext { get; }

    /// <summary>
    /// Optional sender PQ ratchet public key for the recipient's next step.
    /// </summary>
    public PostQuantumPublicPreKey? SenderPostQuantumRatchetKey { get; }

    public EncryptedMessage(
        PublicKey senderRatchetKey,
        uint messageNumber,
        uint previousMessageNumber,
        byte[] ciphertext,
        byte[]? postQuantumCiphertext = null,
        PostQuantumPublicPreKey? senderPostQuantumRatchetKey = null)
    {
        SenderRatchetKey = senderRatchetKey;
        MessageNumber = messageNumber;
        PreviousMessageNumber = previousMessageNumber;
        Ciphertext = ciphertext;
        PostQuantumCiphertext = postQuantumCiphertext;
        SenderPostQuantumRatchetKey = senderPostQuantumRatchetKey;
    }
}
