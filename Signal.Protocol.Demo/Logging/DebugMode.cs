namespace Signal.Protocol.Demo.Logging;

/// <summary>
/// A global switch to enable or disable detailed trace logging at runtime.
/// This is crucial to prevent sensitive key information from being exposed
/// in a non-debug environment.
/// </summary>
public static class DebugMode
{
    /// <summary>
    /// If set to 'true', detailed cryptographic operations will be output via the TraceLogger.
    /// If set to 'false', all logging calls are ineffective.
    /// </summary>
    public static bool Enabled { get; set; } = false;
}