using System;
using System.IO;
using System.IO.Pipes;

class PluginClient
{
    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: PluginClient.exe <PluginName> <Input>");
            Console.WriteLine("\nExamples:");
            Console.WriteLine("  PluginClient.exe Logger \"Hello\"");
            Console.WriteLine("  PluginClient.exe Malicious \"test\"");
            Console.WriteLine("  PluginClient.exe Malicious \"spawn\"");
            return;
        }

        string pluginName = args[0];
        string input = args[1];

        SendCommand(pluginName, input);
    }

    static void SendCommand(string pluginName, string input)
    {
        try
        {
            using var pipeClient = new NamedPipeClientStream(
                ".",
                "VulnerablePluginPipe",
                PipeDirection.InOut);
            Console.WriteLine("[*] Connecting...");
            pipeClient.Connect(5000);
            Console.WriteLine("[+] Connected!");

            using var writer = new StreamWriter(pipeClient) { AutoFlush = true };
            using var reader = new StreamReader(pipeClient);
            string command = $"{pluginName}|{input}";
            writer.WriteLine(command);

            string response = reader.ReadLine();
            Console.WriteLine($"[+] Response: {response}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
        }
    }
}