using System;
using System.IO;
using System.IO.Pipes;

internal class SecurePluginClient
{
    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine("  SECURE PLUGIN CLIENT");
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine("\nUsage: SecurePluginClient.exe <PluginName> <Input>");
            Console.WriteLine("\nExample:");
            Console.WriteLine("  SecurePluginClient.exe LoggerPlugin.dll \"Hello\"");
            return;
        }

        string pluginName = args[0];
        string input = args[1];

        SendSecureCommand(pluginName, input);
    }

    static void SendSecureCommand(string pluginName, string input)
    {
        try
        {
            Console.WriteLine($"[*] Connecting to SECURE pipe...");

            using var pipeClient = new NamedPipeClientStream(
                ".",
                "SecurePluginPipe",
                PipeDirection.InOut,
                PipeOptions.None);
            try
            {
                pipeClient.Connect(5000);
                Console.WriteLine("[✓] Connected!");
            }
            catch (TimeoutException)
            {
                Console.WriteLine("[-] Connection timeout - is host running?");
                return;
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[-] ACCESS DENIED - you are not authorized!");
                Console.WriteLine("    Only approved accounts can connect");
                return;
            }

            using var writer = new StreamWriter(pipeClient) { AutoFlush = true };
            using var reader = new StreamReader(pipeClient);
            string command = $"{pluginName}|{input}";
            Console.WriteLine($"[*] Sending: {command}");
            writer.WriteLine(command);

            string response = reader.ReadLine();

            if (response.StartsWith("ERROR"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[!] {response}");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[✓] {response}");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
        }
    }
}