using NSec.Cryptography;
using System;
using System.Collections.Generic;
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
    private readonly Dictionary<(int, uint), byte[]> _skippedMessageKeys = new();
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

        if (isInitiator)
        {
            _ourSendingRatchetKey = Key.Create(_agreement, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            TraceLogger.LogKey(TraceCategory.RATCHET, "Our initial SendingRatchetKey (Private)", _ourSendingRatchetKey.Export(KeyBlobFormat.RawPrivateKey));
            PerformDHSendingRatchet(remoteInitialX3DHPublicKey);
        }
        else
        {
            _ourSendingRatchetKey = Key.Create(_agreement, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            TraceLogger.LogKey(TraceCategory.RATCHET, "Our initial SendingRatchetKey (Private)", _ourSendingRatchetKey.Export(KeyBlobFormat.RawPrivateKey));
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

        var ciphertext = Encrypt(messageKey, plaintext);
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

        if (_remoteReceivingRatchetKey == null || !message.SenderRatchetKey.Equals(_remoteReceivingRatchetKey))
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
            if (_skippedMessageKeys.Count >= MAX_SKIPPED_KEYS)
            {
                TraceLogger.Log(TraceCategory.ORDERING, $"[!!!] Maximum number of skipped keys ({MAX_SKIPPED_KEYS}) reached. Discarding the oldest.");
                _skippedMessageKeys.Remove(_skippedMessageKeys.Keys.First());
            }

            var (skippedMessageKey, nextReceivingChainKey) = KDFUtil.KDF_CK(_receivingChainKey, "\x01", "\x02");
            _receivingChainKey = nextReceivingChainKey;
            
            var keyId = (_remoteReceivingRatchetKey!.GetHashCode(), _receivingMessageNum);
            _skippedMessageKeys[keyId] = skippedMessageKey;
            _receivingMessageNum++;
            TraceLogger.LogKey(TraceCategory.ORDERING, $"  -> Storing SkippedKey for N={_receivingMessageNum - 1}", skippedMessageKey);
        }

        if (_receivingMessageNum == message.MessageNumber)
        {
            TraceLogger.Log(TraceCategory.RATCHET, $"[{_deviceId}] Reached N={message.MessageNumber}. Decrypting now.");
            var (messageKey, nextReceivingChainKey) = KDFUtil.KDF_CK(_receivingChainKey, "\x01", "\x02");
            _receivingChainKey = nextReceivingChainKey;
            _receivingMessageNum++;
            return Decrypt(messageKey, message.Ciphertext);
        }
        
        TraceLogger.Log(TraceCategory.RATCHET, $"[!!! ERROR at {_deviceId}] Could not decrypt message N={message.MessageNumber}. Current counter is N={_receivingMessageNum}.");
        return null;
    }

    private byte[]? TryDecryptWithSkippedKeys(EncryptedMessage message)
    {
        if (_remoteReceivingRatchetKey == null) return null;
        
        var keyId = (message.SenderRatchetKey.GetHashCode(), message.MessageNumber);
        if (_skippedMessageKeys.TryGetValue(keyId, out var messageKey))
        {
            _skippedMessageKeys.Remove(keyId);
            TraceLogger.Log(TraceCategory.ORDERING, $"[{_deviceId}] Decrypting delayed message N={message.MessageNumber} with stored key.");
            TraceLogger.LogKey(TraceCategory.ORDERING, "  Used SkippedKey", messageKey);
            return Decrypt(messageKey, message.Ciphertext);
        }
        TraceLogger.Log(TraceCategory.ORDERING, $"[{_deviceId}] No matching SkippedKey found for N={message.MessageNumber}.");
        return null;
    }
    
    private void PerformDHReceivingRatchet(EncryptedMessage message)
    {
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

        PerformDHSendingRatchet(_remoteReceivingRatchetKey);
    }
    
    private void PerformDHSendingRatchet(PublicKey remoteRatchetKey)
    {
        _ourSendingRatchetKey.Dispose();
        _ourSendingRatchetKey = Key.Create(_agreement, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        TraceLogger.Log(TraceCategory.RATCHET, $"[{_deviceId}] Performing DH-Send-Ratchet.");
        TraceLogger.LogKey(TraceCategory.RATCHET, "  New Own SendingRatchetKey (Private)", _ourSendingRatchetKey.Export(KeyBlobFormat.RawPrivateKey));

        var dhOutput = KDFUtil.PerformDH(_ourSendingRatchetKey, remoteRatchetKey);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  DH-Result", dhOutput);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  Old RootKey", _rootKey);
        (_rootKey, _sendingChainKey) = KDFUtil.KDF_RK(_rootKey, dhOutput, INFO_ROOT_KEY);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  -> New RootKey", _rootKey);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  -> New SendingChainKey", _sendingChainKey!);
    }

    private byte[] Encrypt(byte[] key, byte[] plaintext)
    {
        var nonce = new byte[_aead.NonceSize];
        RandomNumberGenerator.Fill(nonce);
        using var aesKey = Key.Import(_aead, key, KeyBlobFormat.RawSymmetricKey);
        var ciphertext = _aead.Encrypt(aesKey, nonce, null, plaintext);
        return nonce.Concat(ciphertext).ToArray();
    }

    private byte[]? Decrypt(byte[] key, byte[] combinedCiphertext)
    {
        var nonce = combinedCiphertext.AsSpan(0, _aead.NonceSize).ToArray();
        var ciphertext = combinedCiphertext.AsSpan(_aead.NonceSize).ToArray();
        using var aesKey = Key.Import(_aead, key, KeyBlobFormat.RawSymmetricKey);
        return _aead.Decrypt(aesKey, nonce, null, ciphertext);
    }
}