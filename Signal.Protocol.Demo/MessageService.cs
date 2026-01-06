using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Signal.Protocol.Demo;

/// <summary>
/// Simulates the 1:1 message transport service and manages the Double Ratchet sessions.
/// </summary>
public class MessageService
{
    private readonly PreKeyServer _preKeyServer;
    private GroupMessageService? _groupService;
    private TransportService? _transportService;

    public MessageService(PreKeyServer preKeyServer)
    {
        _preKeyServer = preKeyServer;
    }

    /// <summary>
    /// Sets references to the other services to resolve the circular dependency.
    /// </summary>
    public void SetServiceReferences(GroupMessageService groupService, TransportService transportService)
    {
        _groupService = groupService;
        _transportService = transportService;
    }

    /// <summary>
    /// Initializes a secure 1:1 session between two DEVICES using PQXDH.
    /// </summary>
    public void InitializeSession(Device initiatorDevice, Device responderDevice)
    {
        TraceLogger.Log(TraceCategory.INFO, $"\n>>> Initializing 1:1 session: {initiatorDevice.Id} -> {responderDevice.Id}");
        
        var responderBundle = _preKeyServer.GetPreKeyBundle(responderDevice.Id);
        if (responderBundle == null)
        {
            TraceLogger.Log(TraceCategory.INFO, $"ERROR: Could not find PreKeyBundle for {responderDevice.Id}.");
            return;
        }
        
        var (initiatorSecret, initialBundle, responderInitialRatchetKey) = PQXdhSession.InitiateSession(initiatorDevice, responderBundle);
        var (responderSecret, initiatorInitialRatchetKey) = PQXdhSession.EstablishSession(responderDevice, initialBundle);
        
        if (!initiatorSecret.SequenceEqual(responderSecret))
        {
            throw new InvalidOperationException($"X3DH secrets do not match!");
        }

        var initiatorRatchet = new DoubleRatchet(initiatorDevice.Id, initiatorSecret, initiatorDevice.KeyManager.IdentityAgreementKey, responderInitialRatchetKey, isInitiator: true);
        var responderRatchet = new DoubleRatchet(responderDevice.Id, responderSecret, responderDevice.KeyManager.SignedPreKey, initiatorInitialRatchetKey, isInitiator: false);

        initiatorDevice.PairwiseSessions[responderDevice.Id] = initiatorRatchet;
        responderDevice.PairwiseSessions[initiatorDevice.Id] = responderRatchet;
    }

    /// <summary>
    /// Encrypts a 1:1 message and passes it to the TransportService for delivery.
    /// </summary>
    public void SendMessage(Device senderDevice, Device recipientDevice, string message)
    {
        if (_transportService == null) throw new InvalidOperationException("TransportService is not initialized.");

        if (!senderDevice.PairwiseSessions.TryGetValue(recipientDevice.Id, out var senderRatchet))
        {
            TraceLogger.Log(TraceCategory.INFO, $"[1:1 Send] ERROR: No session found from {senderDevice.Id} to {recipientDevice.Id}.");
            return;
        }
        
        TraceLogger.Log(TraceCategory.INFO, $"--- 1:1 message from {senderDevice.Id} to {recipientDevice.Id}...");
        var plaintext = Encoding.UTF8.GetBytes(message);
        var encryptedMessage = senderRatchet.RatchetEncrypt(plaintext);
        
        _transportService.QueueMessage(recipientDevice, senderDevice.Id, encryptedMessage);
    }
    
    /// <summary>
    /// Is CALLED BY THE TRANSPORT SERVICE to receive and decrypt a message.
    /// </summary>
    public void ReceiveMessage(Device recipientDevice, string senderDeviceId, EncryptedMessage encryptedMessage)
    {
        if (_groupService == null) throw new InvalidOperationException("GroupService is not initialized.");

        if (!recipientDevice.PairwiseSessions.TryGetValue(senderDeviceId, out var receiverRatchet))
        {
            TraceLogger.Log(TraceCategory.INFO, $"[1:1 Receive] ERROR: No session found from {recipientDevice.Id} to {senderDeviceId}.");
            return;
        }

        TraceLogger.Log(TraceCategory.INFO, $"  -> [{recipientDevice.Id}] is decrypting 1:1 message from {senderDeviceId}.");
        var decryptedPlaintextBytes = receiverRatchet.RatchetDecrypt(encryptedMessage);
        
        if (decryptedPlaintextBytes != null)
        {
            var decryptedMessage = Encoding.UTF8.GetString(decryptedPlaintextBytes);
            _groupService.ProcessPairwiseMessage(recipientDevice, senderDeviceId, decryptedMessage);
        }
        else
        {
            TraceLogger.Log(TraceCategory.INFO, $"  -> [!!! ERROR at {recipientDevice.Id}] Decryption of 1:1 message from {senderDeviceId} failed.");
        }
    }
}
