using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Signal.Protocol.Demo.Tests;

/// <summary>
/// Provides a common infrastructure for tests, setting up users, devices, and simulated services.
/// This class initializes the entire demo environment in-memory, handling the dependency injection
/// between the various services. It also provides helpers for message delivery and console output capture.
/// </summary>
public class TestInfrastructure : IDisposable
{
    // Services
    public readonly PreKeyServer PreKeyServer;
    public readonly TransportService TransportService;
    public readonly MessageService PairwiseMessageService;
    public readonly GroupMessageService GroupMessageService;

    // Users & Devices (nullable because they are reset for each test)
    public List<User> AllUsers { get; private set; }
    public User Alice { get; private set; }
    public User Bob { get; private set; }
    public User Charlie { get; private set; }
    public Device AliceMobile { get; private set; }
    public Device AliceTablet { get; private set; }
    public Device BobMobile { get; private set; }
    public Device CharlieMobile { get; private set; }

    // Console Output Capture
    private readonly StringWriter _consoleOutput;
    private readonly TextWriter _originalConsoleOut;

    public TestInfrastructure()
    {
        // --- Service Initialization ---
        // Services are created once and reused. Their state is cleared in ResetState.
        PreKeyServer = new PreKeyServer();
        PairwiseMessageService = new MessageService(PreKeyServer);
        // The GroupMessageService now gets a factory function to retrieve the current user list for each test.
        GroupMessageService = new GroupMessageService(PairwiseMessageService, () => AllUsers);
        TransportService = new TransportService(PairwiseMessageService, GroupMessageService);
        
        // --- Dependency Wiring ---
        PairwiseMessageService.SetServiceReferences(GroupMessageService, TransportService);
        GroupMessageService.SetTransportService(TransportService);

        // --- Console Capture ---
        _originalConsoleOut = Console.Out;
        _consoleOutput = new StringWriter();
        Console.SetOut(_consoleOutput);
        
        // Initial setup is deferred to ResetState, which is called by the test runner before the first test.
        AllUsers = new List<User>();
        Alice = null!; 
        Bob = null!; 
        Charlie = null!;
        AliceMobile = null!;
        AliceTablet = null!;
        BobMobile = null!;
        CharlieMobile = null!;
    }

    /// <summary>
    /// Resets the state of all devices and services to ensure test isolation.
    /// This is called before each test run.
    /// </summary>
    public void ResetState()
    {
        // Clear services' internal states
        GroupMessageService.ClearGroups();
        TransportService.ClearAllMessages();
        PreKeyServer.ClearKeys();
        
        // Clear any console output from previous runs.
        _consoleOutput.GetStringBuilder().Clear();

        // --- User and Device Creation ---
        // Create new users and devices for every test to ensure full isolation.
        Alice = new User("Alice", new[] { "Mobile", "Tablet" });
        Bob = new User("Bob", new[] { "Mobile" });
        Charlie = new User("Charlie", new[] { "Mobile" });
        
        AllUsers = new List<User> { Alice, Bob, Charlie };

        // --- Helper References ---
        AliceMobile = Alice.Devices.First(d => d.Id.EndsWith("Mobile"));
        AliceTablet = Alice.Devices.First(d => d.Id.EndsWith("Tablet"));
        BobMobile = Bob.Devices.First();
        CharlieMobile = Charlie.Devices.First();
        
        // Upload keys for the newly created devices.
        foreach (var user in AllUsers)
        {
            foreach (var device in user.Devices)
            {
                PreKeyServer.UploadDeviceKeys(device);
            }
        }
    }
    
    /// <summary>
    /// Simulates the transport layer delivering all currently queued messages.
    /// </summary>
    public void DeliverAllMessages()
    {
        TransportService.DeliverAllQueuedMessages();
    }
    
    /// <summary>
    /// Gets all text captured from the console since the last call to this method.
    /// </summary>
    public string GetAndClearConsoleOutput()
    {
        var output = _consoleOutput.ToString();
        _consoleOutput.GetStringBuilder().Clear();
        return output;
    }

    public void Dispose()
    {
        // Restore the original console output stream.
        Console.SetOut(_originalConsoleOut);
        _consoleOutput.Dispose();
        
        // Reset debug mode for the next test class.
        DebugMode.Enabled = false;
    }
}

// Xunit collection fixture to share the infrastructure across test classes
[CollectionDefinition("TestCollection")]
public class TestCollection : ICollectionFixture<TestInfrastructure>
{
}