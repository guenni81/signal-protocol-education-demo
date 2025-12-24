using System.Collections.Generic;
using System.Linq;

namespace Signal.Protocol.Demo;

/// <summary>
/// Represents a user who can own multiple devices.
/// </summary>
public class User
{
    /// <summary>
    /// The name of the user, e.g., "Alice".
    /// </summary>
    public string Name { get; }
    
    /// <summary>
    /// The list of devices owned by this user.
    /// </summary>
    public List<Device> Devices { get; }

    /// <summary>
    /// Initializes a new user and adds initial devices to them.
    /// </summary>
    /// <param name="name">The name of the user.</param>
    /// <param name="deviceNames">A list of device names, e.g., ["Mobile", "Tablet"].</param>
    public User(string name, IEnumerable<string> deviceNames)
    {
        Name = name;
        Devices = deviceNames.Select(deviceName => new Device(this, deviceName)).ToList();
    }
}
