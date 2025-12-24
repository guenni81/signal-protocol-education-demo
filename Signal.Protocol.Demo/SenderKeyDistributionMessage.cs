using NSec.Cryptography;
using System.Text.Json.Serialization;

namespace Signal.Protocol.Demo;

/// <summary>
/// Represents a message for distributing Sender Keys.
/// This message is sent over a secure 1:1 channel (Double Ratchet)
/// to communicate a sender's cryptographic state to a group member.
/// </summary>
public class SenderKeyDistributionMessage
{
    /// <summary>
    /// The ID of the group for which this Sender Key is valid.
    /// </summary>
    public string GroupId { get; }
    
    /// <summary>
    /// The ID of the device that will use this Sender Key.
    /// </summary>
    public string SenderDeviceId { get; }

    /// <summary>
    /// The public part of the sender's signing key as raw bytes.
    /// </summary>
    public byte[] SenderSigningPublicKeyBytes { get; }

    /// <summary>
    /// The initial Chain Key for the sender chain.
    /// </summary>
    public byte[] SenderChainKey { get; }
    
    /// <summary>
    /// Reconstructs a distribution message from its individual parts.
    /// This constructor is used by the JSON deserializer.
    /// </summary>
    [JsonConstructor]
    public SenderKeyDistributionMessage(string groupId, string senderDeviceId, byte[] senderSigningPublicKeyBytes, byte[] senderChainKey)
    {
        GroupId = groupId;
        SenderDeviceId = senderDeviceId;
        SenderSigningPublicKeyBytes = senderSigningPublicKeyBytes;
        SenderChainKey = senderChainKey;
    }
}