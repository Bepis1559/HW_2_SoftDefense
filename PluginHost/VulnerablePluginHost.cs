using System;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Collections.Generic;
using System.Linq;
using PluginHost;

class VulnerablePluginHost
{
    // Secret в паметта - достъпен чрез reflection
    private static string _secretApiKey = "";
    private static readonly List<IPlugin> _loadedPlugins = [];

    static void Main(string[] args)
    {
        LoadSecrets();
        LoadPlugins();
        StartNamedPipeServer();
    }

    static void LoadSecrets()
    {
        string secretPath = Path.Combine("secrets", "secret.txt");

        try
        {
            Directory.CreateDirectory("secrets");

            if (!File.Exists(secretPath))
            {
                _secretApiKey = "sk-prod-super-secret-12345";
                File.WriteAllText(secretPath, _secretApiKey);
            }
            else
            {
                _secretApiKey = File.ReadAllText(secretPath).Trim();
            }

            Console.WriteLine($"[+] Secret loaded: {_secretApiKey.Substring(0, 10)}...");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
        }
    }

    static void LoadPlugins()
    {
        string pluginDir = "plugins";
        Directory.CreateDirectory(pluginDir);

        Console.WriteLine($"\n[*] Loading plugins from: {pluginDir}");

        // LoadFrom без проверка
        var dllFiles = Directory.GetFiles(pluginDir, "*.dll");

        if (dllFiles.Length == 0)
        {
            Console.WriteLine("[!] No plugins found");
            return;
        }

        foreach (var dllPath in dllFiles)
        {
            try
            {
                //  Без signature verification
                Assembly assembly = Assembly.LoadFrom(dllPath);

                var pluginTypes = assembly.GetTypes()
                    .Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract);

                foreach (var type in pluginTypes)
                {
                    var plugin = (IPlugin)Activator.CreateInstance(type);
                    _loadedPlugins.Add(plugin);
                    Console.WriteLine($"[+] Loaded: {plugin.Name}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error loading {Path.GetFileName(dllPath)}: {ex.Message}");
            }
        }
    }

    static void StartNamedPipeServer()
    {
        Console.WriteLine("\n[*] Starting Named Pipe server...\n");

        while (true)
        {
            try
            {
                //  Няма ACL защита!
                using var pipeServer = new NamedPipeServerStream(
                    "VulnerablePluginPipe",
                    PipeDirection.InOut,
                    1);
                Console.WriteLine("[*] Waiting for connection...");
                pipeServer.WaitForConnection();
                Console.WriteLine("[+] Client connected!");

                using (var reader = new StreamReader(pipeServer))
                using (var writer = new StreamWriter(pipeServer) { AutoFlush = true })
                {
                    string command = reader.ReadLine();
                    Console.WriteLine($"[*] Command: {command}");

                    var parts = command?.Split('|') ?? new string[0];

                    if (parts.Length >= 2)
                    {
                        string pluginName = parts[0];
                        string input = string.Join("|", parts.Skip(1));

                        var plugin = _loadedPlugins.FirstOrDefault(
                            p => p.Name.Equals(pluginName, StringComparison.OrdinalIgnoreCase));

                        if (plugin != null)
                        {
                            // Няма timeout, resource limits!
                            plugin.Execute(input);
                            writer.WriteLine("OK");
                        }
                        else
                        {
                            writer.WriteLine($"ERROR: Plugin '{pluginName}' not found");
                        }
                    }
                    else
                    {
                        writer.WriteLine("ERROR: Invalid format");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }
    }
}