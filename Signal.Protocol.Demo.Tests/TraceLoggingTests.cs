namespace Signal.Protocol.Demo.Tests;

[Collection("TestCollection")]
public class TraceLoggingTests
{
    private readonly TestInfrastructure _infra;

    public TraceLoggingTests(TestInfrastructure infra)
    {
        _infra = infra;
        // Ensure debug mode is off before state is reset, so that key generation is not logged.
        DebugMode.Enabled = false;
        _infra.ResetState();
    }

    [Fact]
    public void When_DebugMode_Is_Enabled_Should_Produce_Logs()
    {
        // ARRANGE
        DebugMode.Enabled = true;
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;
        
        // ACT
        _infra.PairwiseMessageService.InitializeSession(alice, bob);
        _infra.DeliverAllMessages();
        
        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        Assert.NotEmpty(output);
        Assert.Contains("[X3DH    ]", output); // Category is padded to 8 characters
        Assert.Contains("[INSECURE DEMO ONLY – PRIVATE KEY OUTPUT]", output);
        Assert.Contains("Shared Secret", output);
    }
    
    [Fact]
    public void When_DebugMode_Is_Disabled_Should_Not_Produce_Logs()
    {
        // ARRANGE
        // DebugMode is disabled by default by the fixture, but we make it explicit.
        DebugMode.Enabled = false;
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;
        
        // ACT
        _infra.PairwiseMessageService.InitializeSession(alice, bob);
        _infra.DeliverAllMessages();
        
        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        Assert.Empty(output);
    }
    
    [Fact]
    public void GroupActions_Should_Produce_Group_Logs_When_DebugMode_Is_Enabled()
    {
        // ARRANGE
        DebugMode.Enabled = true;
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;
        string groupName = "Logging Group";
        var memberNames = new List<string> { alice.Owner.Name, bob.Owner.Name };
        
        _infra.PairwiseMessageService.InitializeSession(alice, bob);
        _infra.DeliverAllMessages();
        _infra.GetAndClearConsoleOutput(); // Clear setup logs

        // ACT
        _infra.GroupMessageService.CreateGroup(groupName, alice.Id, memberNames);
        _infra.DeliverAllMessages();

        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        Assert.NotEmpty(output);
        Assert.Contains("[GROUP   ]", output); // Padded to 8 characters
        Assert.Contains($"'{groupName}' with ID '", output);
    }
}

