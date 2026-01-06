using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;

namespace Signal.Protocol.Demo;

/// <summary>
/// Implements a simplified ML-KEM Braid protocol on top of the Double Ratchet.
/// Each DH ratchet step is combined with a PQ encapsulation step.
/// </summary>
public sealed class HybridDoubleRatchet
{
    private const string INFO_MSG_KEY = "Signal-Message";
    private const string INFO_ROOT_KEY = "Signal-Braid-Root";
    private const string PQ_TRACE_PREFIX = "INSECURE DEMO ONLY – POST-QUANTUM TRACE";

    private byte[] _rootKey;
    private Key _ourSendingRatchetKey;
    private PublicKey? _remoteReceivingRatchetKey;
    private byte[]? _sendingChainKey;
    private byte[]? _receivingChainKey;
    private uint _sendingMessageNum;
    private uint _receivingMessageNum;
    private uint _previousSendingMessageNum;

    private readonly Dictionary<(int, uint), byte[]> _skippedMessageKeys = new();
    private const int MAX_SKIPPED_KEYS = 50;

    private readonly string _deviceId;
    private readonly Key _ourInitialX3DHKey;
    private readonly bool _isInitiator;

    private readonly PQRatchetState _pqState;
    private byte[]? _pendingPqCiphertext;
    private PostQuantumPublicPreKey? _pendingPqSenderKey;

    private static readonly AeadAlgorithm _aead = AeadAlgorithm.Aes256Gcm;
    private static readonly KeyAgreementAlgorithm _agreement = KeyAgreementAlgorithm.X25519;
    private static readonly KeyDerivationAlgorithm _hkdf = KeyDerivationAlgorithm.HkdfSha256;

    public HybridDoubleRatchet(
        string deviceId,
        byte[] sharedSecret,
        Key ourInitialX3DHKey,
        PublicKey remoteInitialX3DHPublicKey,
        bool isInitiator,
        PostQuantumPublicPreKey? initialRemotePqKey,
        PostQuantumPreKey? initialLocalPqKey = null,
        MLKemParameters? pqParameters = null)
    {
        _deviceId = deviceId;
        _isInitiator = isInitiator;
        _rootKey = sharedSecret;
        _remoteReceivingRatchetKey = remoteInitialX3DHPublicKey;
        _ourInitialX3DHKey = ourInitialX3DHKey;

        var parameters = pqParameters ?? MLKemParameters.ml_kem_512;
        var localKeyPair = initialLocalPqKey != null
            ? PQRatchetKeyPair.FromPreKey(initialLocalPqKey)
            : PQRatchetKeyPair.Generate(parameters);
        _pqState = new PQRatchetState(localKeyPair, initialRemotePqKey);

        TraceLogger.Log(TraceCategory.RATCHET, $"--- [{_deviceId}] New HybridDoubleRatchet Session ---");
        LogPqKey(TraceCategory.RATCHET, "Initial RootKey (from PQXDH)", _rootKey);

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
        var message = new EncryptedMessage(
            _ourSendingRatchetKey.PublicKey,
            _sendingMessageNum - 1,
            _previousSendingMessageNum,
            ciphertext,
            _pendingPqCiphertext,
            _pendingPqSenderKey);

        if (_pendingPqCiphertext != null)
        {
            LogPq(TraceCategory.RATCHET, $"[{_deviceId}] Attached PQ ciphertext ({_pendingPqCiphertext.Length} bytes) to message header.");
        }

        _pendingPqCiphertext = null;
        _pendingPqSenderKey = null;

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
            TraceLogger.Log(TraceCategory.RATCHET, $"[{_deviceId}] New remote ratchet key received. Performing hybrid ratchet step.");
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

        if (message.SenderPostQuantumRatchetKey.HasValue)
        {
            _pqState.SetRemotePublicKey(message.SenderPostQuantumRatchetKey.Value);
            LogPq(TraceCategory.RATCHET, $"[{_deviceId}] Updated remote PQ ratchet key.");
        }

        if (message.PostQuantumCiphertext == null)
        {
            throw new InvalidOperationException("Missing PQ ciphertext for hybrid ratchet step.");
        }

        var pqSecret = _pqState.Decapsulate(message.PostQuantumCiphertext);
        LogPqKey(TraceCategory.RATCHET, "  PQ Ratchet Secret", pqSecret);
        LogPq(TraceCategory.RATCHET, $"[{_deviceId}] PQ ciphertext size: {message.PostQuantumCiphertext.Length} bytes.");

        Key ourPrivateKey = (_receivingChainKey == null && !_isInitiator) ? _ourInitialX3DHKey : _ourSendingRatchetKey;
        TraceLogger.LogKey(TraceCategory.RATCHET, "  Used Our PrivateKey for DH", ourPrivateKey.Export(KeyBlobFormat.RawPrivateKey));

        var dhOutput1 = KDFUtil.PerformDH(ourPrivateKey, _remoteReceivingRatchetKey);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  DH-Result", dhOutput1);
        LogPqKey(TraceCategory.RATCHET, "  Old RootKey", _rootKey);
        (_rootKey, _receivingChainKey) = KdfHybridRootAndChain(_rootKey, dhOutput1, pqSecret);
        LogPqKey(TraceCategory.RATCHET, "  -> New RootKey", _rootKey);
        LogPqKey(TraceCategory.RATCHET, "  -> New ReceivingChainKey", _receivingChainKey!);

        PerformDHSendingRatchet(_remoteReceivingRatchetKey);
    }

    private void PerformDHSendingRatchet(PublicKey remoteRatchetKey)
    {
        _ourSendingRatchetKey.Dispose();
        _ourSendingRatchetKey = Key.Create(_agreement, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        TraceLogger.Log(TraceCategory.RATCHET, $"[{_deviceId}] Performing DH-Send-Ratchet.");
        TraceLogger.LogKey(TraceCategory.RATCHET, "  New Own SendingRatchetKey (Private)", _ourSendingRatchetKey.Export(KeyBlobFormat.RawPrivateKey));

        var parameters = PostQuantumKeyManager.ResolveParameters(_pqState.OurKeyPair.ParameterName);
        _pqState.RotateOurKeyPair(parameters);
        var ourPqPublicKey = _pqState.OurKeyPair.ToPublicPreKey();
        LogPq(TraceCategory.RATCHET, $"[{_deviceId}] Advanced PQ ratchet and generated new PQ key.");
        LogPqKey(TraceCategory.RATCHET, "  PQ Ratchet PublicKey", ourPqPublicKey.PublicKey);

        var (pqCiphertext, pqSecret) = _pqState.EncapsulateToRemote();
        LogPqKey(TraceCategory.RATCHET, "  PQ Ratchet Secret", pqSecret);
        LogPq(TraceCategory.RATCHET, $"[{_deviceId}] PQ ciphertext size: {pqCiphertext.Length} bytes.");

        _pendingPqCiphertext = pqCiphertext;
        _pendingPqSenderKey = ourPqPublicKey;

        var dhOutput = KDFUtil.PerformDH(_ourSendingRatchetKey, remoteRatchetKey);
        TraceLogger.LogKey(TraceCategory.RATCHET, "  DH-Result", dhOutput);
        LogPqKey(TraceCategory.RATCHET, "  Old RootKey", _rootKey);
        (_rootKey, _sendingChainKey) = KdfHybridRootAndChain(_rootKey, dhOutput, pqSecret);
        LogPqKey(TraceCategory.RATCHET, "  -> New RootKey", _rootKey);
        LogPqKey(TraceCategory.RATCHET, "  -> New SendingChainKey", _sendingChainKey!);
    }

    private static (byte[] RootKey, byte[] ChainKey) KdfHybridRootAndChain(byte[] rootKey, byte[] dhOutput, byte[] pqSecret)
    {
        var ikm = Concat(rootKey, dhOutput, pqSecret);
        var infoBytes = System.Text.Encoding.UTF8.GetBytes(INFO_ROOT_KEY);
        byte[] derivedBytes = _hkdf.DeriveBytes(ikm, salt: null, infoBytes, 64);

        byte[] newRootKey = new byte[32];
        Array.Copy(derivedBytes, 0, newRootKey, 0, 32);

        byte[] newChainKey = new byte[32];
        Array.Copy(derivedBytes, 32, newChainKey, 0, 32);

        return (newRootKey, newChainKey);
    }

    private static byte[] Concat(params byte[]?[] arrays)
    {
        var result = new List<byte>();
        foreach (var arr in arrays)
        {
            if (arr != null) result.AddRange(arr);
        }
        return result.ToArray();
    }

    private void LogPq(TraceCategory category, string message)
    {
        TraceLogger.Log(category, $"{PQ_TRACE_PREFIX} {message}");
    }

    private void LogPqKey(TraceCategory category, string keyName, byte[] key)
    {
        TraceLogger.LogKey(category, $"{PQ_TRACE_PREFIX} {keyName}", key);
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
