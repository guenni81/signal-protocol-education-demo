using Signal.Protocol.Demo;
using System;
using System.Collections.Generic;
using System.Linq;

public class Program
{
    public static void Main(string[] args)
    {
        // =================================================================
        // PHASE 1: DEBUG MODE ENABLED
        // =================================================================
        DebugMode.Enabled = true;

        TraceLogger.Log(TraceCategory.INFO, "=================================================================");
        TraceLogger.Log(TraceCategory.INFO, "     Signal Protocol: Detailed Trace-Logging Demo");
        TraceLogger.Log(TraceCategory.INFO, "=================================================================");
        TraceLogger.Log(TraceCategory.INFO, "Debug mode is ENABLED. All cryptographic steps will be logged.");
        TraceLogger.Log(TraceCategory.INFO, "-----------------------------------------------------------------\n");

        // --- Setup ---
        TraceLogger.Log(TraceCategory.INFO, ">>> Setup - Creating users, devices, and services.");
        var alice = new User("Alice", new[] { "Mobile", "Desktop" });
        var bob = new User("Bob", new[] { "Mobile" });
        var charlie = new User("Charlie", new[] { "Mobile", "Tablet" });
        var allUsers = new List<User> { alice, bob, charlie };
        var allDevices = allUsers.SelectMany(u => u.Devices).ToList();

        var preKeyServer = new PreKeyServer();
        foreach (var device in allDevices)
        {
            preKeyServer.UploadDeviceKeys(device);
        }

        var messageService = new MessageService(preKeyServer);
        var groupService = new GroupMessageService(messageService, () => allUsers);
        var transportService = new TransportService(messageService, groupService);

        messageService.SetServiceReferences(groupService, transportService);
        groupService.SetTransportService(transportService);

        TraceLogger.Log(TraceCategory.INFO, $"{allUsers.Count} users with {allDevices.Count} devices, PreKeyServer, and all services are initialized.\n");

        // --- 1:1 Session Initialization (X3DH) ---
        TraceLogger.Log(TraceCategory.INFO, ">>> Establishing 1:1 sessions (X3DH) between all devices.");
        for (int i = 0; i < allDevices.Count; i++)
        {
            for (int j = i + 1; j < allDevices.Count; j++)
            {
                messageService.InitializeSession(allDevices[i], allDevices[j]);
            }
        }

        transportService.DeliverAllQueuedMessages();
        TraceLogger.Log(TraceCategory.INFO, "All X3DH handshakes completed.");

        // --- PING Phase to Initialize All Ratchets ---
        // A responder cannot send until it has received the first message.
        // We send "pings" from the initiator to the responder to ensure every session is bidirectional.
        TraceLogger.Log(TraceCategory.INFO, "\n>>> Sending pings to initialize all ratchets for bidirectional communication.");
        for (int i = 0; i < allDevices.Count; i++)
        {
            for (int j = i + 1; j < allDevices.Count; j++)
            {
                messageService.SendMessage(allDevices[i], allDevices[j], "Session-Setup-Ping");
            }
        }
        transportService.DeliverAllQueuedMessages();
        TraceLogger.Log(TraceCategory.INFO, "All 1:1 channels are established and ready for communication.\n");

        // --- 1:1 Out-of-Order ---
        TraceLogger.Log(TraceCategory.INFO, ">>> 1:1 Communication with Out-of-Order Delivery.");
        var alicesMobile = alice.Devices.First();
        var bobsMobile = bob.Devices.First();

        TraceLogger.Log(TraceCategory.INFO, $"Alice (Mobile) sends 3 messages to Bob (Mobile)...");
        messageService.SendMessage(alicesMobile, bobsMobile, "Message 1: The first one.");
        messageService.SendMessage(alicesMobile, bobsMobile, "Message 2: The second one.");
        messageService.SendMessage(alicesMobile, bobsMobile, "Message 3: The third one.");
        TraceLogger.Log(TraceCategory.INFO, "All 3 messages are queued in the TransportService.");

        var deliveryOrder = new List<int> { 2, 0, 1 };
        TraceLogger.Log(TraceCategory.INFO, $"\nDelivering to Bob in wrong order: Message 3, 1, 2");
        transportService.DeliverMessagesToDevice(bobsMobile.Id, deliveryOrder);
        TraceLogger.Log(TraceCategory.INFO, "All messages were successfully decrypted by Bob despite the wrong order.\n");

        // --- Group Chat Out-of-Order ---
        TraceLogger.Log(TraceCategory.INFO, ">>> Group Chat with Out-of-Order Delivery.");
        var groupName = "Signal Demo Group";
        var memberNames = new List<string> { "Alice", "Bob", "Charlie" };
        groupService.CreateGroup(groupName, alicesMobile.Id, memberNames);

        TraceLogger.Log(TraceCategory.INFO, "\nDistributing initial group keys to all members...");
        transportService.DeliverAllQueuedMessages();
        TraceLogger.Log(TraceCategory.INFO, "Group created and initial keys distributed.\n");

        TraceLogger.Log(TraceCategory.INFO, $"Alice (Mobile) sends 5 messages to the group '{groupName}'...");
        for (int i = 1; i <= 5; i++)
        {
            groupService.SendGroupMessage(alicesMobile.Id, groupName, $"Group Message #{i}");
        }
        TraceLogger.Log(TraceCategory.INFO, "All 5 group messages are queued.");

        var groupDeliveryOrder = new List<int> { 1, 3, 4, 0, 2 };
        TraceLogger.Log(TraceCategory.INFO, $"\nDelivering to Bob and Charlie in wrong order: Message 2, 4, 5, 1, 3");

        var recipients = bob.Devices.Concat(charlie.Devices);
        foreach (var device in recipients)
        {
            TraceLogger.Log(TraceCategory.INFO, $"--- Delivery to {device.Id} ---");
            transportService.DeliverMessagesToDevice(device.Id, groupDeliveryOrder);
        }

        TraceLogger.Log(TraceCategory.INFO, "\nAll group messages were successfully decrypted on all devices of Bob and Charlie.\n");
        transportService.DeliverAllQueuedMessages();

        // =================================================================
        // PHASE 2: DEBUG MODE DISABLED
        // =================================================================
        DebugMode.Enabled = false;

        TraceLogger.Log(TraceCategory.INFO, "=================================================================");
        TraceLogger.Log(TraceCategory.INFO, "     DEBUG MODE DISABLED");
        TraceLogger.Log(TraceCategory.INFO, "=================================================================");
        Console.WriteLine("\nDebug mode is now DISABLED. No sensitive logs will be printed from now on.");

        TraceLogger.Log(TraceCategory.INFO, "Sending a final message from Bob to Alice to demonstrate silent mode...");
        Console.WriteLine("\nBob is sending a final message...");
        groupService.DistributeSenderKeys(bobsMobile.Id, groupName);
        groupService.SendGroupMessage(bobsMobile.Id, groupName, "Final test message!");

        // Delivery without detailed logging
        transportService.DeliverAllQueuedMessages();
        Console.WriteLine("\nMessages delivered. No [RATCHET] or [GROUP] logs should have appeared.");

        TraceLogger.Log(TraceCategory.INFO, "=================================================================");
        Console.WriteLine("                  Demonstration finished.");
        TraceLogger.Log(TraceCategory.INFO, "=================================================================");
    }
}