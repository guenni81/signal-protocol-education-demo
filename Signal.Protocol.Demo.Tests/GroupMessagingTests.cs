namespace Signal.Protocol.Demo.Tests;

[Collection("TestCollection")]
public class GroupMessagingTests
{
    private readonly TestInfrastructure _infra;

    public GroupMessagingTests(TestInfrastructure infra)
    {
        _infra = infra;
        _infra.ResetState();
    }

    [Fact]
    public void Group_Should_Be_Created_And_Initial_Message_Sent()
    {
        // ARRANGE
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;
        var charlie = _infra.CharlieMobile;
        string groupName = "Test Group 1";
        string welcomeMessage = "Welcome to the group!";

        // ARRANGE - Establish pairwise sessions first, as they are used to transport the sender keys.
        _infra.PairwiseMessageService.InitializeSession(alice, bob);
        _infra.PairwiseMessageService.InitializeSession(alice, charlie);
        _infra.DeliverAllMessages();
        _infra.GetAndClearConsoleOutput();

        // ACT
        // 1. Alice creates a group. The creator must be in the member list.
        var memberNames = new List<string> { alice.Owner.Name, bob.Owner.Name, charlie.Owner.Name };
        _infra.GroupMessageService.CreateGroup(groupName, alice.Id, memberNames);
        
        // 2. Deliver the distribution messages (which are sent 1:1).
        _infra.DeliverAllMessages();
        
        // 3. Alice sends the first message to the group.
        _infra.GroupMessageService.SendGroupMessage(alice.Id, groupName, welcomeMessage);
        
        // 4. Deliver the group message.
        _infra.DeliverAllMessages();

        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        
        // Check that Bob and Charlie processed Alice's sender key
        Assert.Contains($"  -> [{bob.Id}] is processing Sender Key from {alice.Id} for group '{groupName}'.", output);
        Assert.Contains($"  -> [{charlie.Id}] is processing Sender Key from {alice.Id} for group '{groupName}'.", output);
        
        // Check that Bob and Charlie received the message
        Assert.Contains($"    [{bob.Id}] Successfully decrypted: '{welcomeMessage}'", output);
        Assert.Contains($"    [{charlie.Id}] Successfully decrypted: '{welcomeMessage}'", output);
    }
    
    [Fact]
    public void Second_Member_Should_Be_Able_To_Distribute_Keys()
    {
        // ARRANGE
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;
        var charlie = _infra.CharlieMobile;
        string groupName = "Test Group 2";

        // ARRANGE - Sessions must be initiated by Alice so she can distribute the first key.
        // The sessions created on Bob and Charlie as responders are sufficient for them to send keys back.
        _infra.PairwiseMessageService.InitializeSession(alice, bob);
        _infra.PairwiseMessageService.InitializeSession(alice, charlie);
        _infra.DeliverAllMessages();
        _infra.GetAndClearConsoleOutput();
        
        // ACT
        // 1. Alice creates the group. This will use the A->B and A->C sessions.
        var memberNames = new List<string> { alice.Owner.Name, bob.Owner.Name, charlie.Owner.Name };
        _infra.GroupMessageService.CreateGroup(groupName, alice.Id, memberNames);
        _infra.DeliverAllMessages();

        // 2. Now, Bob distributes his own sender key to the group.
        // This will use the B->A (from the A->B init) and will create a new B->C session.
        _infra.PairwiseMessageService.InitializeSession(bob, charlie); // Bob needs to be able to talk to Charlie
        _infra.DeliverAllMessages();
        _infra.GroupMessageService.DistributeSenderKeys(bob.Id, groupName);
        _infra.DeliverAllMessages();
        
        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();

        // Check that Alice and Charlie processed Bob's sender key
        Assert.Contains($"  -> [{alice.Id}] is processing Sender Key from {bob.Id} for group '{groupName}'.", output);
        Assert.Contains($"  -> [{charlie.Id}] is processing Sender Key from {bob.Id} for group '{groupName}'.", output);
    }
    
    
    [Fact]
    public void OutOfOrder_Group_Messages_Should_Be_Decrypted()
    {
        // ARRANGE - Same initial setup as the first test
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;
        string groupName = "Test Group 4";
        _infra.PairwiseMessageService.InitializeSession(alice, bob);
        _infra.DeliverAllMessages();
        var memberNames = new List<string> { alice.Owner.Name, bob.Owner.Name };
        _infra.GroupMessageService.CreateGroup(groupName, alice.Id, memberNames);
        _infra.DeliverAllMessages();
        _infra.GetAndClearConsoleOutput();

        // ACT
        // 1. Alice sends three group messages
        string msg1 = "Group First";
        string msg2 = "Group Second";
        string msg3 = "Group Third";
        _infra.GroupMessageService.SendGroupMessage(alice.Id, groupName, msg1);
        _infra.GroupMessageService.SendGroupMessage(alice.Id, groupName, msg2);
        _infra.GroupMessageService.SendGroupMessage(alice.Id, groupName, msg3);
        
// Deliver them to Bob out of order (3, then 1, then 2)
        _infra.TransportService.DeliverMessagesToDevice(bob.Id, new() { 2, 0, 1 });

        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        Assert.Contains($"    [{bob.Id}] Successfully decrypted: '{msg1}'", output);
        Assert.Contains($"    [{bob.Id}] Successfully decrypted: '{msg2}'", output);
        Assert.Contains($"    [{bob.Id}] Successfully decrypted: '{msg3}'", output);
    }
    
    [Fact]
    public void Group_Message_Should_Be_Received_By_Multi_Device_User()
    {
        // ARRANGE
        var aliceMobile = _infra.AliceMobile;
        var aliceTablet = _infra.AliceTablet;
        var bob = _infra.BobMobile;
        string groupName = "Multi-Device Group";
        string message = "Message for Alice's devices";
        var memberNames = new List<string> { aliceMobile.Owner.Name, bob.Owner.Name };

        // ARRANGE - Establish sessions from Bob (sender) to both of Alice's devices for key distribution
        _infra.PairwiseMessageService.InitializeSession(bob, aliceMobile);
        _infra.PairwiseMessageService.InitializeSession(bob, aliceTablet);
        _infra.DeliverAllMessages();

        // ARRANGE - Bob creates the group. This sends the sender key to both of Alice's devices.
        _infra.GroupMessageService.CreateGroup(groupName, bob.Id, memberNames);
        _infra.DeliverAllMessages();
        _infra.GetAndClearConsoleOutput();

        // ACT
        _infra.GroupMessageService.SendGroupMessage(bob.Id, groupName, message);
        _infra.DeliverAllMessages();

        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        Assert.Contains($"    [{aliceMobile.Id}] Successfully decrypted: '{message}'", output);
        Assert.Contains($"    [{aliceTablet.Id}] Successfully decrypted: '{message}'", output);
    }
}

