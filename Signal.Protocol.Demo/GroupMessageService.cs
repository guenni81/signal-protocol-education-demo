using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;

namespace Signal.Protocol.Demo;

/// <summary>
/// Coordinates the creation of groups and the sending/receiving of group messages.
/// </summary>
public class GroupMessageService
{
    private readonly MessageService _pairwiseMessageService;
    private readonly Dictionary<string, GroupSession> _groups = new();
    private readonly Func<List<User>> _allUsers;
    private TransportService? _transportService;

    private static readonly AeadAlgorithm _aead = AeadAlgorithm.Aes256Gcm;

    public GroupMessageService(MessageService pairwiseMessageService, Func<List<User>> allUsers)
    {
        _pairwiseMessageService = pairwiseMessageService;
        _allUsers = allUsers;
    }

    public void SetTransportService(TransportService transportService)
    {
        _transportService = transportService;
    }

    /// <summary>
    /// FOR TESTING: Clears all created groups.
    /// </summary>
    public void ClearGroups()
    {
        _groups.Clear();
    }

    /// <summary>
    /// Creates a new group and distributes the creator's initial Sender Keys.
    /// </summary>
    public void CreateGroup(string groupName, string creatorDeviceId, List<string> memberNames)
    {
        var groupSession = _groups.Values.FirstOrDefault(g => g.Name == groupName);
        if (groupSession == null)
        {
            TraceLogger.Log(TraceCategory.INFO, $"\n########## GROUP CREATION: '{groupName}' by {creatorDeviceId} ##########");
            var members = _allUsers().Where(u => memberNames.Contains(u.Name)).ToList();
            groupSession = new GroupSession(groupName, members);
            _groups[groupSession.Id] = groupSession;
            TraceLogger.Log(TraceCategory.INFO, $"Group '{groupSession.Name}' with ID '{groupSession.Id}' and {members.Count} members created.");
        }
        
        DistributeSenderKeys(creatorDeviceId, groupName);
    }
    
    /// <summary>
    /// Distributes the Sender Keys of a device to all other devices in the group.
    /// </summary>
    public void DistributeSenderKeys(string senderDeviceId, string groupName)
    {
        var group = _groups.Values.First(g => g.Name == groupName);
        var senderDevice = group.GetAllDevices().First(d => d.Id == senderDeviceId);
        
        TraceLogger.Log(TraceCategory.GROUP, $"\n-----> {senderDeviceId} is distributing Sender Keys for group '{group.Name}'...");

        var senderState = SenderKeyState.Create(senderDeviceId);
        senderDevice.OwnSenderKeyStates[group.Id] = senderState;
        
        // The SigningKey object is guaranteed not to be null here as it's created in Create().
        var distMsg = new SenderKeyDistributionMessage(
            group.Id, 
            senderDeviceId, 
            senderState.SigningKey!.PublicKey.Export(KeyBlobFormat.RawPublicKey), 
            senderState.ChainKey
        );
        var distMsgPayload = JsonSerializer.Serialize(distMsg);

        foreach (var memberDevice in group.GetAllDevices())
        {
            if (memberDevice.Id == senderDevice.Id) continue;
            
            TraceLogger.Log(TraceCategory.GROUP, $"  -> Sending key to {memberDevice.Id} via 1:1 channel.");
            _pairwiseMessageService.SendMessage(senderDevice, memberDevice, $"skdist:{distMsgPayload}");
        }
        TraceLogger.Log(TraceCategory.GROUP, $"-----> Distribution of Sender Keys for {senderDeviceId} complete.");
    }

    /// <summary>
    /// Processes an incoming 1:1 message.
    /// </summary>
    public void ProcessPairwiseMessage(Device recipientDevice, string fromDeviceId, string messageContent)
    {
        if (messageContent.StartsWith("skdist:"))
        {
            var payload = messageContent.Substring("skdist:".Length);
            var distMsg = JsonSerializer.Deserialize<SenderKeyDistributionMessage>(payload);

            if (distMsg != null)
            {
                var groupName = _groups.Values.First(g => g.Id == distMsg.GroupId).Name;
                TraceLogger.Log(TraceCategory.GROUP, $"  -> [{recipientDevice.Id}] is processing Sender Key from {distMsg.SenderDeviceId} for group '{groupName}'.");

                var signingPublicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, distMsg.SenderSigningPublicKeyBytes, KeyBlobFormat.RawPublicKey);
                
                var loggingId = $"'{recipientDevice.Id}' for '{distMsg.SenderDeviceId}'";
                var state = SenderKeyState.CreateFromDistributedKeys(signingPublicKey, distMsg.SenderChainKey, loggingId);
                
                var key = $"{distMsg.GroupId}:{distMsg.SenderDeviceId}";
                recipientDevice.ReceivedSenderKeyStates[key] = state;
            }
        }
        else
        {
            TraceLogger.Log(TraceCategory.INFO, $"  -> [{recipientDevice.Id}] processing 1:1 message from {fromDeviceId}: '{messageContent}'");
        }
    }

    /// <summary>
    /// Creates, encrypts, signs, and "sends" a group message.
    /// </summary>
    public void SendGroupMessage(string senderDeviceId, string groupName, string plaintext)
    {
        if (_transportService == null) throw new InvalidOperationException("TransportService is not initialized.");
        
        var group = _groups.Values.First(g => g.Name == groupName);
        var senderDevice = group.GetAllDevices().First(d => d.Id == senderDeviceId);
        
        if (!senderDevice.OwnSenderKeyStates.TryGetValue(group.Id, out var senderState) || senderState.SigningKey == null)
        {
            TraceLogger.Log(TraceCategory.INFO, $"[ERROR] {senderDeviceId} has no Sender Keys for group '{group.Name}' and cannot send.");
            return;
        }
        
        TraceLogger.Log(TraceCategory.INFO, $"\n<<<<<<<<<< GROUP MESSAGE from {senderDeviceId} to '{group.Name}': '{plaintext}' >>>>>>>>>>");
        
        var messageKey = senderState.SenderRatchetStep();
        var currentCounter = senderState.MessageCounter - 1;

        var nonce = new byte[AeadAlgorithm.Aes256Gcm.NonceSize];
        RandomNumberGenerator.Fill(nonce);
        using var aesKey = Key.Import(_aead, messageKey, KeyBlobFormat.RawSymmetricKey);
        var ad = BuildAssociatedData(group.Id, senderDeviceId, currentCounter);
        var ciphertext = _aead.Encrypt(aesKey, nonce, ad, Encoding.UTF8.GetBytes(plaintext));
        var combinedCiphertext = nonce.Concat(ciphertext).ToArray();
        
        var signature = SignatureAlgorithm.Ed25519.Sign(senderState.SigningKey, combinedCiphertext);
        
        var groupMessage = new GroupMessage(group.Id, senderDeviceId, currentCounter, signature, combinedCiphertext);

        TraceLogger.Log(TraceCategory.GROUP, $"          (Message Counter: {currentCounter}, 1x encrypted & signed)");

        var recipients = group.GetAllDevices().Where(d => d.Id != senderDevice.Id);
        _transportService.QueueGroupMessage(groupMessage, recipients);
    }

    /// <summary>
    /// Simulates the reception of a group message.
    /// </summary>
    public void ReceiveGroupMessage(Device recipientDevice, GroupMessage groupMessage)
    {
        TraceLogger.Log(TraceCategory.GROUP, $"  -> [{recipientDevice.Id}] is receiving a group message...");
        var key = $"{groupMessage.GroupId}:{groupMessage.SenderDeviceId}";
        
        if (recipientDevice.ReceivedSenderKeyStates.TryGetValue(key, out var senderState))
        {
            if (!SignatureAlgorithm.Ed25519.Verify(senderState.SigningPublicKey, groupMessage.Ciphertext, groupMessage.Signature))
            {
                TraceLogger.Log(TraceCategory.GROUP, $"    [!!! ERROR at {recipientDevice.Id}] Invalid signature!");
                return;
            }
            TraceLogger.Log(TraceCategory.GROUP, $"    [{recipientDevice.Id}] Signature verified.");
            
            var messageKey = senderState.GetReceiverMessageKey(groupMessage.MessageCounter);
            if (messageKey == null)
            {
                TraceLogger.Log(TraceCategory.GROUP, $"    [!!! ERROR at {recipientDevice.Id}] Could not derive Message Key for counter {groupMessage.MessageCounter}.");
                return;
            }
            
            var nonce = groupMessage.Ciphertext.AsSpan(0, _aead.NonceSize).ToArray();
            var ciphertext = groupMessage.Ciphertext.AsSpan(_aead.NonceSize).ToArray();
            using var aesKey = Key.Import(_aead, messageKey, KeyBlobFormat.RawSymmetricKey);
            var ad = BuildAssociatedData(groupMessage.GroupId, groupMessage.SenderDeviceId, groupMessage.MessageCounter);
            var plaintextBytes = _aead.Decrypt(aesKey, nonce, ad, ciphertext);

            if (plaintextBytes != null)
            {
                var plaintext = Encoding.UTF8.GetString(plaintextBytes);
                TraceLogger.Log(TraceCategory.GROUP, $"    [{recipientDevice.Id}] Successfully decrypted: '{plaintext}'");
            }
            else
            {
                TraceLogger.Log(TraceCategory.GROUP, $"    [!!! ERROR at {recipientDevice.Id}] Decryption failed!");
            }
        }
        else
        {
            TraceLogger.Log(TraceCategory.GROUP, $"    [!!! ERROR at {recipientDevice.Id}] No Sender Key found for {groupMessage.SenderDeviceId} in group {groupMessage.GroupId}!");
        }
    }

    private static byte[] BuildAssociatedData(string groupId, string senderDeviceId, uint messageCounter)
    {
        var groupIdBytes = Encoding.UTF8.GetBytes(groupId);
        var senderIdBytes = Encoding.UTF8.GetBytes(senderDeviceId);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(groupIdBytes.Length);
        writer.Write(groupIdBytes);
        writer.Write(senderIdBytes.Length);
        writer.Write(senderIdBytes);
        writer.Write(messageCounter);
        return stream.ToArray();
    }
}
