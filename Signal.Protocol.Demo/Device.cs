using System.Collections.Concurrent;
using System.Collections.Generic;

namespace Signal.Protocol.Demo;

/// <summary>
/// Represents a single device belonging to a user.
/// Each device manages its own cryptographic keys and sessions.
/// </summary>
public class Device
{
    /// <summary>
    /// A unique ID for the device, e.g., "Alice-Mobile".
    /// </summary>
    public string Id { get; }
    
    /// <summary>
    /// The user who owns this device.
    /// </summary>
    public User Owner { get; }
    
    /// <summary>
    /// The key manager for the X3DH keys of this specific device.
    /// </summary>
    public KeyManager KeyManager { get; }

    /// <summary>
    /// The key manager for the ML-KEM Post-Quantum prekeys of this device.
    /// </summary>
    public PostQuantumKeyManager PostQuantumKeyManager { get; }

    /// <summary>
    /// Manages the 1:1 Double Ratchet sessions of this device with other devices.
    /// The key is the ID of the other device.
    /// </summary>
    public ConcurrentDictionary<string, DoubleRatchet> PairwiseSessions { get; }
    
    /// <summary>
    /// Manages the received Sender Key states for each group and sender.
    /// The key is a combination of Group-ID and Sender-Device-ID, e.g., "group-id:sender-id".
    /// </summary>
    public ConcurrentDictionary<string, SenderKeyState> ReceivedSenderKeyStates { get; }
    
    /// <summary>
    /// Manages its own Sender Key states for each group this device sends to.
    /// The key is the Group-ID.
    /// </summary>
    public ConcurrentDictionary<string, SenderKeyState> OwnSenderKeyStates { get; }

    /// <summary>
    /// Initializes a new device.
    /// </summary>
    /// <param name="owner">The user who owns the device.</param>
    /// <param name="deviceName">A name for the device, e.g., "Mobile".</param>
    public Device(User owner, string deviceName)
    {
        Owner = owner;
        Id = $"{owner.Name}-{deviceName}";
        KeyManager = new KeyManager();
        PostQuantumKeyManager = new PostQuantumKeyManager();
        PairwiseSessions = new ConcurrentDictionary<string, DoubleRatchet>();
        ReceivedSenderKeyStates = new ConcurrentDictionary<string, SenderKeyState>();
        OwnSenderKeyStates = new ConcurrentDictionary<string, SenderKeyState>();
    }
}
