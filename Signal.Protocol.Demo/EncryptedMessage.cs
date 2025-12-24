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

    public EncryptedMessage(PublicKey senderRatchetKey, uint messageNumber, uint previousMessageNumber, byte[] ciphertext)
    {
        SenderRatchetKey = senderRatchetKey;
        MessageNumber = messageNumber;
        PreviousMessageNumber = previousMessageNumber;
        Ciphertext = ciphertext;
    }
}