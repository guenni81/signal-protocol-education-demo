namespace Signal.Protocol.Demo.Tests;

public class SenderKeyStateTests
{
    [Fact]
    public void SkippedKeys_Should_Evict_Oldest_When_Limit_Exceeded()
    {
        // ARRANGE
        var state = SenderKeyState.Create("Test-Device");

        // ACT
        // Request a far-future message key to force skipped-key caching.
        state.GetReceiverMessageKey(60);

        // ASSERT
        Assert.Equal(50, state.SkippedMessageKeys.Count);
        Assert.False(state.SkippedMessageKeys.ContainsKey(0));
        Assert.False(state.SkippedMessageKeys.ContainsKey(9));
        Assert.True(state.SkippedMessageKeys.ContainsKey(10));
        Assert.True(state.SkippedMessageKeys.ContainsKey(59));
    }
}
