using System;
using System.Collections.Generic;
using System.Linq;

namespace Signal.Protocol.Demo;

/// <summary>
/// Represents the metadata of a group.
/// </summary>
public class GroupSession
{
    /// <summary>
    /// A unique ID for the group.
    /// </summary>
    public string Id { get; }
    
    /// <summary>
    /// The name of the group.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// The list of users who are members of the group.
    /// </summary>
    public List<User> Members { get; }

    /// <summary>
    /// Initializes a new group session.
    /// </summary>
    /// <param name="name">The name of the group.</param>
    /// <param name="members">The initial members of the group.</param>
    public GroupSession(string name, List<User> members)
    {
        Id = Guid.NewGuid().ToString(); // Creates a simple, unique ID for the demo.
        Name = name;
        Members = members;
    }

    /// <summary>
    /// Helper method to get a flat list of all devices from all members of the group.
    /// </summary>
    /// <returns>A list of all devices in the group.</returns>
    public List<Device> GetAllDevices()
    {
        // Uses LINQ to query the device list from each member and flatten them into a single list.
        return Members.SelectMany(member => member.Devices).ToList();
    }
}