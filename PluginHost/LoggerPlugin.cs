using PluginHost;
using System;

public class LoggerPlugin : IPlugin
{
    public string Name => "Logger";

    public void Execute(string input)
    {
        Console.WriteLine($"[Logger] Message: {input}");
        Console.WriteLine($"[Logger] Time: {DateTime.Now}");
    }
}