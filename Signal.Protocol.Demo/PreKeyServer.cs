using NSec.Cryptography;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace Signal.Protocol.Demo;

/// <summary>
/// Simulates a server that stores and delivers public Pre-Key bundles for each DEVICE.
/// </summary>
public class PreKeyServer
{
    // The keys of the dictionaries are now the unique device IDs.
    private readonly Dictionary<string, (PublicKey SigningKey, PublicKey AgreementKey)> _identityKeys = new();
    private readonly Dictionary<string, (PublicKey Key, byte[] Signature)> _signedPreKeys = new();
    private readonly Dictionary<string, ConcurrentQueue<(string KeyId, PublicKey Key)>> _oneTimePreKeys = new();
    private readonly Dictionary<string, PostQuantumPublicPreKey> _postQuantumPreKeys = new();
    private readonly Dictionary<string, ConcurrentQueue<PostQuantumPublicPreKey>> _postQuantumOneTimePreKeys = new();

    /// <summary>
    /// FOR TESTING: Clears all keys from the server.
    /// </summary>
    public void ClearKeys()
    {
        _identityKeys.Clear();
        _signedPreKeys.Clear();
        _oneTimePreKeys.Clear();
        _postQuantumPreKeys.Clear();
        _postQuantumOneTimePreKeys.Clear();
    }

    /// <summary>
    /// Uploads the keys of a specific device to the server.
    /// </summary>
    /// <param name="device">The device whose keys are being uploaded.</param>
    public void UploadDeviceKeys(Device device)
    {
        _identityKeys[device.Id] = (device.KeyManager.IdentitySigningKey.PublicKey, device.KeyManager.IdentityAgreementKey.PublicKey);
        _signedPreKeys[device.Id] = (device.KeyManager.SignedPreKey.PublicKey, device.KeyManager.SignedPreKeySignature);
        
        var deviceOneTimeKeysQueue = new ConcurrentQueue<(string KeyId, PublicKey Key)>();
        var deviceOneTimeKeysDict = device.KeyManager.GetPublicOneTimePreKeys();
        foreach (var pair in deviceOneTimeKeysDict)
        {
            deviceOneTimeKeysQueue.Enqueue((pair.Key, pair.Value));
        }
        _oneTimePreKeys[device.Id] = deviceOneTimeKeysQueue;
        
        if (DebugMode.Enabled)
        {
            TraceLogger.Log(TraceCategory.KEYGEN, $"Uploaded keys for {device.Id}.");
        }

        UploadPostQuantumKeys(device);
    }

    /// <summary>
    /// Uploads the Post-Quantum ML-KEM keys of a specific device to the server.
    /// </summary>
    public void UploadPostQuantumKeys(Device device)
    {
        _postQuantumPreKeys[device.Id] = device.PostQuantumKeyManager.PublicIdentityKey;
        var devicePostQuantumKeysQueue = new ConcurrentQueue<PostQuantumPublicPreKey>();
        var devicePostQuantumKeysDict = device.PostQuantumKeyManager.GetPublicOneTimePreKeys();
        foreach (var pair in devicePostQuantumKeysDict)
        {
            devicePostQuantumKeysQueue.Enqueue(pair.Value);
        }
        _postQuantumOneTimePreKeys[device.Id] = devicePostQuantumKeysQueue;

        if (DebugMode.Enabled)
        {
            TraceLogger.Log(TraceCategory.KEYGEN, $"Uploaded PQ keys for {device.Id}.");
        }
    }

    /// <summary>
    /// Retrieves the Pre-Key bundle for a specific device.
    /// </summary>
    /// <param name="deviceId">The ID of the device for which the bundle is being retrieved.</param>
    /// <returns>The PreKeyBundle, or null if the device was not found.</returns>
    public PreKeyBundle? GetPreKeyBundle(string deviceId)
    {
        if (!_identityKeys.ContainsKey(deviceId)) return null;

        var (publicIdentitySigningKey, publicIdentityAgreementKey) = _identityKeys[deviceId];
        var (publicSignedPreKey, signedPreKeySignature) = _signedPreKeys[deviceId];

        // Try to retrieve a One-Time PreKey. If none are left, that's also fine.
        (string KeyId, PublicKey Key)? oneTimePreKey = null;
        if (_oneTimePreKeys.TryGetValue(deviceId, out var deviceOtpQueue) && deviceOtpQueue.TryDequeue(out var otp))
        {
            oneTimePreKey = otp;
        }

        PostQuantumPublicPreKey? postQuantumOneTimePreKey = null;
        if (_postQuantumOneTimePreKeys.TryGetValue(deviceId, out var devicePqQueue) && devicePqQueue.TryDequeue(out var pqOtp))
        {
            postQuantumOneTimePreKey = pqOtp;
        }

        PostQuantumPublicPreKey? postQuantumPreKey = null;
        if (_postQuantumPreKeys.TryGetValue(deviceId, out var pqIdentity))
        {
            postQuantumPreKey = pqIdentity;
        }

        return new PreKeyBundle(
            deviceId,
            publicIdentitySigningKey,
            publicIdentityAgreementKey,
            publicSignedPreKey,
            signedPreKeySignature,
            oneTimePreKey,
            postQuantumPreKey,
            postQuantumOneTimePreKey);
    }

    /// <summary>
    /// Retrieves the Post-Quantum Pre-Key bundle for a specific device.
    /// </summary>
    public PostQuantumPreKeyBundle? GetPostQuantumPreKeyBundle(string deviceId)
    {
        if (!_postQuantumPreKeys.TryGetValue(deviceId, out var identityKey))
        {
            return null;
        }

        PostQuantumPublicPreKey? oneTimePreKey = null;
        if (_postQuantumOneTimePreKeys.TryGetValue(deviceId, out var devicePqQueue) && devicePqQueue.TryDequeue(out var pqOtp))
        {
            oneTimePreKey = pqOtp;
        }

        return new PostQuantumPreKeyBundle(deviceId, identityKey, oneTimePreKey);
    }
}
