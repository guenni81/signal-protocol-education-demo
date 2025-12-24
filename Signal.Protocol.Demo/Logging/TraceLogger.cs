using System;
using System.Text;

namespace Signal.Protocol.Demo.Logging;

/// <summary>
/// A static logger for emitting detailed trace information for demo purposes.
/// The logger is only active when `DebugMode.Enabled` is set to `true`.
/// It can output sensitive cryptographic data, such as private keys, and prefixes
/// these entries with a clear warning.
/// </summary>
public static class TraceLogger
{
    private static readonly object _lock = new();

    /// <summary>
    /// Logs a message if debug mode is enabled.
    /// </summary>
    /// <param name="category">The category of the log entry.</param>
    /// <param name="message">The message to log.</param>
    /// <param name="isSensitive">Indicates whether the message contains sensitive data (e.g., private keys).</param>
    public static void Log(TraceCategory category, string message, bool isSensitive = false)
    {
        if (!DebugMode.Enabled)
        {
            return;
        }

        lock (_lock)
        {
            var warning = isSensitive ? " [INSECURE DEMO ONLY – PRIVATE KEY OUTPUT]" : "";
            var color = isSensitive ? ConsoleColor.Red : GetCategoryColor(category);

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"[{DateTime.Now:HH:mm:ss.fff}] ");
            
            Console.ForegroundColor = color;
            Console.Write($"[{category,-8}]");
            
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine($"{warning} {message}");

            Console.ResetColor();
        }
    }

    /// <summary>
    /// A helper method to log a byte array (typically a key) as a Base64 string.
    /// This log is always marked as sensitive.
    /// </summary>
    /// <param name="category">The category of the log entry.</param>
    /// <param name="keyName">The name of the key (e.g., "Root Key").</param>
    /// <param name="key">The key as a byte array.</param>
    public static void LogKey(TraceCategory category, string keyName, byte[] key)
    {
        if (!DebugMode.Enabled)
        {
            return;
        }
        
        var keyBase64 = Convert.ToBase64String(key);
        Log(category, $"{keyName}: {keyBase64}", isSensitive: true);
    }

    private static ConsoleColor GetCategoryColor(TraceCategory category)
    {
        return category switch
        {
            TraceCategory.KEYGEN => ConsoleColor.Cyan,
            TraceCategory.X3DH => ConsoleColor.Magenta,
            TraceCategory.RATCHET => ConsoleColor.Yellow,
            TraceCategory.GROUP => ConsoleColor.Green,
            TraceCategory.ORDERING => ConsoleColor.Blue,
            TraceCategory.INFO => ConsoleColor.White,
            _ => ConsoleColor.Gray
        };
    }
}