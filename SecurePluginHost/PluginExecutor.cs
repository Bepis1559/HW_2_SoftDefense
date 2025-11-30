using System;
using System.IO;
using System.Reflection;
using System.Linq;
using System.Security;
using SecurePluginHost;

class PluginExecutor
{
    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: PluginExecutor.exe <pluginPath> <input>");
            Environment.Exit(1);
        }

        string pluginPath = args[0];
        string input = args[1];

        try
        {
            if (!File.Exists(pluginPath))
            {
                Console.Error.WriteLine($"ERROR: Plugin not found: {pluginPath}");
                Environment.Exit(2);
            }

            // SANDBOXING: Проверка на restrictions
            CheckSandboxRestrictions();

            Console.WriteLine($"[Sandbox] Loading: {Path.GetFileName(pluginPath)}");

            // ЗАЩИТА D: LoadFrom с full path (anti-hijacking)
            Assembly assembly = Assembly.LoadFrom(pluginPath);

            var pluginTypes = assembly.GetTypes()
                .Where(t => typeof(IPlugin).IsAssignableFrom(t) &&
                           !t.IsInterface &&
                           !t.IsAbstract);

            if (!pluginTypes.Any())
            {
                Console.Error.WriteLine("ERROR: No IPlugin implementation found");
                Environment.Exit(3);
            }

            var pluginType = pluginTypes.First();
            var plugin = (IPlugin)Activator.CreateInstance(pluginType);

            Console.WriteLine($"[Sandbox] Executing: {plugin.Name}");

            try
            {
                plugin.Execute(input);
                Console.WriteLine($"[Sandbox] Completed successfully");
            }
            catch (SecurityException secEx)
            {
                Console.Error.WriteLine($"[Sandbox] SECURITY VIOLATION: {secEx.Message}");
                Environment.Exit(4);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Sandbox] Plugin error: {ex.Message}");
                Environment.Exit(5);
            }

            Environment.Exit(0);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Sandbox] Fatal error: {ex.Message}");
            Environment.Exit(99);
        }
    }

    // Проверка на sandbox ограничения
    static void CheckSandboxRestrictions()
    {
        try
        {
            // Опит да достъпим secrets (трябва да FAIL-не!)
            string secretsPath = Path.Combine(
                Directory.GetCurrentDirectory(),
                "secrets",
                "secret.txt");

            if (File.Exists(secretsPath))
            {
                try
                {
                    File.ReadAllText(secretsPath);
                    Console.Error.WriteLine("[!] WARNING: Sandbox can access secrets!");
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("[✓] Sandbox: Cannot access secrets (GOOD)");
                }
            }
        }
        catch
        {
            // Ignore
        }
    }
}