namespace Signal.Protocol.Demo;

/// <summary>
/// Represents an encrypted group message distributed to all members.
/// </summary>
public class GroupMessage
{
    /// <summary>
    /// The ID of the group to which this message belongs.
    /// </summary>
    public string GroupId { get; }

    /// <summary>
    /// The ID of the device that sent this message.
    /// </summary>
    public string SenderDeviceId { get; }

    /// <summary>
    /// The message counter from the sender chain.
    /// </summary>
    public uint MessageCounter { get; }
    
    /// <summary>
    /// The signature of the message to ensure sender authenticity.
    /// </summary>
    public byte[] Signature { get; }

    /// <summary>
    /// The encrypted message content (Ciphertext).
    /// </summary>
    public byte[] Ciphertext { get; }

    /// <summary>
    /// Initializes a new group message.
    /// </summary>
    public GroupMessage(string groupId, string senderDeviceId, uint messageCounter, byte[] signature, byte[] ciphertext)
    {
        GroupId = groupId;
        SenderDeviceId = senderDeviceId;
        MessageCounter = messageCounter;
        Signature = signature;
        Ciphertext = ciphertext;
    }
}