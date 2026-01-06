using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Signal.Protocol.Demo;

/// <summary>
/// Implements the state and logic for a single Double Ratchet session.
/// </summary>
public class DoubleRatchet
{
    // Constants for the KDF info strings
    private const string INFO_MSG_KEY = "Signal-Message";
    private const string INFO_ROOT_KEY = "Signal-Root";
    
    // Current state of the ratchets
    private byte[] _rootKey;
    private Key _ourSendingRatchetKey; 
    private PublicKey? _remoteReceivingRatchetKey;
    private byte[]? _sendingChainKey;
    private byte[]? _receivingChainKey;
    private uint _sendingMessageNum;
    private uint _receivingMessageNum;
    private uint _previousSendingMessageNum;
    
    // Storage for skipped message keys
    private readonly Dictionary<(string, uint), byte[]> _skippedMessageKeys = new();
    private readonly LinkedList<(string, uint)> _skippedMessageKeyOrder = new();
    private readonly Dictionary<(string, uint), LinkedListNode<(string, uint)>> _skippedMessageKeyNodes = new();
    private const int MAX_SKIPPED_KEYS = 50;

    // Metadata for logging
    private readonly string _deviceId;
    private readonly Key _ourInitialX3DHKey;
    private readonly bool _isInitiator;

    private static readonly AeadAlgorithm _aead = AeadAlgorithm.Aes256Gcm;
    private static readonly KeyAgreementAlgorithm _agreement = KeyAgreementAlgorithm.X25519;

    public DoubleRatchet(string deviceId, byte[] sharedSecret, Key ourInitialX3DHKey, PublicKey remoteInitialX3DHPublicKey, bool isInitiator)
    {
        _deviceId = deviceId;
        _isInitiator = isInitiator;
        _rootKey = sharedSecret;
        _remoteReceivingRatchetKey = remoteInitialX3DHPublicKey;
        _ourInitialX3DHKey = ourInitialX3DHKey;
        
        TraceLogger.Log(TraceCategory.RATCHET, $"--- [{_deviceId}] New DoubleRatchet Session ---");
        TraceLogger.LogKey(TraceCategory.RATCHET, "Initial RootKey (from X3DH)", _rootKey);

        _ourSendingRatchetKey = isInitiator
            ? ourInitialX3DHKey
            : Key.Create(_agreement, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        TraceLogger.LogKey(TraceCategory.RATCHET, "Our initial SendingRatchetKey (Private)", _ourSendingRatchetKey.Export(KeyBlobFormat.RawPrivateKey));

        if (isInitiator)
        {
            PerformDHSendingRatchet(remoteInitialX3DHPublicKey, rotateKeyPair: false);
        }
        else
        {
            TraceLogger.Log(TraceCategory.RATCHET, $"[{_deviceId}] Responder is waiting for the first message to initialize the receiving chain.");
        }
    }
    
    public EncryptedMessage RatchetEncrypt(byte[] plaintext)
    {
        if (_sendingChainKey == null) throw new InvalidOperationException("Sending chain has not been initialized.");

        TraceLogger.Log(TraceCategory.RATCHET, $"[{_deviceId}] Encrypt: Sending message N={_sendingMessageNum}");
        TraceLogger.LogKey(TraceCategory.RATCHET, "  Current SendingChainKey", _sendingChainKey);

        var (messageKey, nextChainKey) = KDFUtil.KDF_CK(_sendingChainKey, "\x01", "\x02");
        _sendingChainKey = nextChainKey;
        _sendingMessageNum++;
        
        TraceLogger.LogKey(TraceCategory.RATCHET, "  -> Derived MessageKey", messageKey);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  -> Next SendingChainKey", _sendingChainKey);

        var ad = BuildAssociatedData(_ourSendingRatchetKey.PublicKey, _sendingMessageNum - 1, _previousSendingMessageNum);
        var ciphertext = Encrypt(messageKey, plaintext, ad);
        var message = new EncryptedMessage(_ourSendingRatchetKey.PublicKey, _sendingMessageNum - 1, _previousSendingMessageNum, ciphertext);
        
        return message;
    }

    public byte[]? RatchetDecrypt(EncryptedMessage message)
    {
        TraceLogger.Log(TraceCategory.RATCHET, $"[{_deviceId}] Decrypt: Receiving message with N={message.MessageNumber}, PN={message.PreviousMessageNumber}");

        var decrypted = TryDecryptWithSkippedKeys(message);
        if (decrypted != null)
        {
            return decrypted;
        }

        if (_remoteReceivingRatchetKey == null || _receivingChainKey == null || !message.SenderRatchetKey.Equals(_remoteReceivingRatchetKey))
        {
            TraceLogger.Log(TraceCategory.RATCHET, $"[{_deviceId}] New remote ratchet key received. Performing DH ratchet step.");
            PerformDHReceivingRatchet(message);
        }
        
        decrypted = TryDecryptWithSkippedKeys(message);
        if (decrypted != null)
        {
            return decrypted;
        }
        
        if (_receivingChainKey == null) throw new InvalidOperationException("Receiving chain has not been initialized.");

        TraceLogger.Log(TraceCategory.ORDERING, $"[{_deviceId}] Expected N={_receivingMessageNum}, but got N={message.MessageNumber}. Advancing chain...");
        while (_receivingMessageNum < message.MessageNumber)
        {
            var (skippedMessageKey, nextReceivingChainKey) = KDFUtil.KDF_CK(_receivingChainKey, "\x01", "\x02");
            _receivingChainKey = nextReceivingChainKey;

            StoreSkippedMessageKey(_remoteReceivingRatchetKey!, _receivingMessageNum, skippedMessageKey);
            _receivingMessageNum++;
            TraceLogger.LogKey(TraceCategory.ORDERING, $"  -> Storing SkippedKey for N={_receivingMessageNum - 1}", skippedMessageKey);
        }

        if (_receivingMessageNum == message.MessageNumber)
        {
            TraceLogger.Log(TraceCategory.RATCHET, $"[{_deviceId}] Reached N={message.MessageNumber}. Decrypting now.");
            var (messageKey, nextReceivingChainKey) = KDFUtil.KDF_CK(_receivingChainKey, "\x01", "\x02");
            _receivingChainKey = nextReceivingChainKey;
            _receivingMessageNum++;
            var ad = BuildAssociatedData(message.SenderRatchetKey, message.MessageNumber, message.PreviousMessageNumber);
            return Decrypt(messageKey, message.Ciphertext, ad);
        }
        
        TraceLogger.Log(TraceCategory.RATCHET, $"[!!! ERROR at {_deviceId}] Could not decrypt message N={message.MessageNumber}. Current counter is N={_receivingMessageNum}.");
        return null;
    }

    private byte[]? TryDecryptWithSkippedKeys(EncryptedMessage message)
    {
        if (_remoteReceivingRatchetKey == null) return null;
        
        var keyId = (GetRatchetKeyId(message.SenderRatchetKey), message.MessageNumber);
        if (_skippedMessageKeys.TryGetValue(keyId, out var messageKey))
        {
            _skippedMessageKeys.Remove(keyId);
            if (_skippedMessageKeyNodes.TryGetValue(keyId, out var node))
            {
                _skippedMessageKeyOrder.Remove(node);
                _skippedMessageKeyNodes.Remove(keyId);
            }
            TraceLogger.Log(TraceCategory.ORDERING, $"[{_deviceId}] Decrypting delayed message N={message.MessageNumber} with stored key.");
            TraceLogger.LogKey(TraceCategory.ORDERING, "  Used SkippedKey", messageKey);
            var ad = BuildAssociatedData(message.SenderRatchetKey, message.MessageNumber, message.PreviousMessageNumber);
            return Decrypt(messageKey, message.Ciphertext, ad);
        }
        TraceLogger.Log(TraceCategory.ORDERING, $"[{_deviceId}] No matching SkippedKey found for N={message.MessageNumber}.");
        return null;
    }
    
    private void PerformDHReceivingRatchet(EncryptedMessage message)
    {
        if (_receivingChainKey != null && _remoteReceivingRatchetKey != null)
        {
            SkipMessageKeys(message.PreviousMessageNumber);
        }

        _previousSendingMessageNum = _sendingMessageNum;
        _sendingMessageNum = 0;
        _receivingMessageNum = 0;

        TraceLogger.Log(TraceCategory.RATCHET, $"[{_deviceId}] DH-Receive-Ratchet: PN is set to {_previousSendingMessageNum}.");
        
        _remoteReceivingRatchetKey = message.SenderRatchetKey;
        TraceLogger.LogKey(TraceCategory.RATCHET, "  New RemoteReceivingRatchetKey", _remoteReceivingRatchetKey.Export(KeyBlobFormat.RawPublicKey));

        Key ourPrivateKey = (_receivingChainKey == null && !_isInitiator) ? _ourInitialX3DHKey : _ourSendingRatchetKey;
        TraceLogger.LogKey(TraceCategory.RATCHET, "  Used Our PrivateKey for DH", ourPrivateKey.Export(KeyBlobFormat.RawPrivateKey));
        
        var dhOutput1 = KDFUtil.PerformDH(ourPrivateKey, _remoteReceivingRatchetKey);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  DH-Result", dhOutput1);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  Old RootKey", _rootKey);
        (_rootKey, _receivingChainKey) = KDFUtil.KDF_RK(_rootKey, dhOutput1, INFO_ROOT_KEY);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  -> New RootKey", _rootKey);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  -> New ReceivingChainKey", _receivingChainKey!);

        PerformDHSendingRatchet(_remoteReceivingRatchetKey, rotateKeyPair: true);
    }
    
    private void PerformDHSendingRatchet(PublicKey remoteRatchetKey, bool rotateKeyPair)
    {
        if (rotateKeyPair)
        {
            _ourSendingRatchetKey.Dispose();
            _ourSendingRatchetKey = Key.Create(_agreement, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            TraceLogger.Log(TraceCategory.RATCHET, $"[{_deviceId}] Performing DH-Send-Ratchet.");
            TraceLogger.LogKey(TraceCategory.RATCHET, "  New Own SendingRatchetKey (Private)", _ourSendingRatchetKey.Export(KeyBlobFormat.RawPrivateKey));
        }
        else
        {
            TraceLogger.Log(TraceCategory.RATCHET, $"[{_deviceId}] Performing initial DH-Send-Ratchet with X3DH key.");
        }

        var dhOutput = KDFUtil.PerformDH(_ourSendingRatchetKey, remoteRatchetKey);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  DH-Result", dhOutput);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  Old RootKey", _rootKey);
        (_rootKey, _sendingChainKey) = KDFUtil.KDF_RK(_rootKey, dhOutput, INFO_ROOT_KEY);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  -> New RootKey", _rootKey);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  -> New SendingChainKey", _sendingChainKey!);
    }

    private void SkipMessageKeys(uint until)
    {
        TraceLogger.Log(TraceCategory.ORDERING, $"[{_deviceId}] Skipping message keys up to PN={until}.");
        while (_receivingMessageNum < until)
        {
            var (skippedMessageKey, nextReceivingChainKey) = KDFUtil.KDF_CK(_receivingChainKey!, "\x01", "\x02");
            _receivingChainKey = nextReceivingChainKey;
            StoreSkippedMessageKey(_remoteReceivingRatchetKey!, _receivingMessageNum, skippedMessageKey);
            TraceLogger.LogKey(TraceCategory.ORDERING, $"  -> Storing SkippedKey for N={_receivingMessageNum}", skippedMessageKey);
            _receivingMessageNum++;
        }
    }

    private void StoreSkippedMessageKey(PublicKey ratchetKey, uint messageNumber, byte[] skippedKey)
    {
        var keyId = (GetRatchetKeyId(ratchetKey), messageNumber);
        _skippedMessageKeys[keyId] = skippedKey;
        var node = _skippedMessageKeyOrder.AddLast(keyId);
        _skippedMessageKeyNodes[keyId] = node;

        while (_skippedMessageKeyOrder.Count > MAX_SKIPPED_KEYS)
        {
            var oldestNode = _skippedMessageKeyOrder.First!;
            _skippedMessageKeyOrder.RemoveFirst();
            _skippedMessageKeyNodes.Remove(oldestNode.Value);
            _skippedMessageKeys.Remove(oldestNode.Value);
            TraceLogger.Log(TraceCategory.ORDERING, $"[!!!] Maximum number of skipped keys ({MAX_SKIPPED_KEYS}) reached. Discarding the oldest.");
        }
    }

    private static string GetRatchetKeyId(PublicKey ratchetKey)
    {
        var keyBytes = ratchetKey.Export(KeyBlobFormat.RawPublicKey);
        return Convert.ToBase64String(keyBytes);
    }

    private static byte[] BuildAssociatedData(PublicKey senderRatchetKey, uint messageNumber, uint previousMessageNumber)
    {
        var senderKeyBytes = senderRatchetKey.Export(KeyBlobFormat.RawPublicKey);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(senderKeyBytes.Length);
        writer.Write(senderKeyBytes);
        writer.Write(messageNumber);
        writer.Write(previousMessageNumber);
        return stream.ToArray();
    }

    private byte[] Encrypt(byte[] key, byte[] plaintext, byte[] associatedData)
    {
        var nonce = new byte[_aead.NonceSize];
        RandomNumberGenerator.Fill(nonce);
        using var aesKey = Key.Import(_aead, key, KeyBlobFormat.RawSymmetricKey);
        var ciphertext = _aead.Encrypt(aesKey, nonce, associatedData, plaintext);
        return nonce.Concat(ciphertext).ToArray();
    }

    private byte[]? Decrypt(byte[] key, byte[] combinedCiphertext, byte[] associatedData)
    {
        var nonce = combinedCiphertext.AsSpan(0, _aead.NonceSize).ToArray();
        var ciphertext = combinedCiphertext.AsSpan(_aead.NonceSize).ToArray();
        using var aesKey = Key.Import(_aead, key, KeyBlobFormat.RawSymmetricKey);
        return _aead.Decrypt(aesKey, nonce, associatedData, ciphertext);
    }
}
