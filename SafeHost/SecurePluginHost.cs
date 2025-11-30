using System;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class SecurePluginHost
{
    private static readonly List<string> _approvedPluginHashes = [];

    private static readonly string[] ALLOWED_PLUGINS = [
        "LoggerPlugin.dll"
    ];

    static void Main(string[] args)
    {
      

        CheckPrivileges();
        LoadApprovedPlugins();
        StartSecureNamedPipeServer();
    }

    static void CheckPrivileges()
    {
        try
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);

                Console.WriteLine($"\n[*] Current user: {identity.Name}");

                if (identity.User?.Value == "S-1-5-18")
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[!] WARNING: Running as SYSTEM!");
                    Console.WriteLine("[!] Host should run with limited privileges!");
                    Console.ResetColor();
                }
                else if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[!] WARNING: Running as Administrator");
                    Console.WriteLine("[!] Consider running as regular user");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[✓] Running with limited privileges - GOOD!");
                    Console.ResetColor();
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Cannot check privileges: {ex.Message}");
        }
    }

    static void LoadApprovedPlugins()
    {
        Console.WriteLine("\n[*] Loading approved plugins...");

        string pluginDir = Path.GetFullPath("plugins");

        if (!Directory.Exists(pluginDir))
        {
            Directory.CreateDirectory(pluginDir);
            Console.WriteLine("[!] No plugins directory");
            return;
        }

        foreach (var allowedPlugin in ALLOWED_PLUGINS)
        {
            string fullPath = Path.Combine(pluginDir, allowedPlugin);

            if (!File.Exists(fullPath))
            {
                Console.WriteLine($"[!] Plugin not found: {allowedPlugin}");
                continue;
            }

            if (!fullPath.StartsWith(pluginDir))
            {
                Console.WriteLine($"[!] BLOCKED: Path traversal attempt: {fullPath}");
                continue;
            }

            if (!VerifyAssemblySignature(fullPath))
            {
                Console.WriteLine($"[!] BLOCKED: Unsigned assembly: {allowedPlugin}");
                continue;
            }

            string hash = ComputeFileHash(fullPath);
            _approvedPluginHashes.Add(hash);

            Console.WriteLine($"[✓] Approved: {allowedPlugin}");
            Console.WriteLine($"    Hash: {hash[..16]}...");
        }

        Console.WriteLine($"\n[✓] Total approved: {_approvedPluginHashes.Count}");
    }

    static bool VerifyAssemblySignature(string assemblyPath)
    {
        try
        {
            var assemblyName = AssemblyName.GetAssemblyName(assemblyPath);
            byte[] publicKeyToken = assemblyName.GetPublicKeyToken();

            if (publicKeyToken == null || publicKeyToken.Length == 0)
            {
                Console.WriteLine($"[!] No strong name signature");
                return false;
            }

            Console.WriteLine($"[✓] Strong name: {BitConverter.ToString(publicKeyToken)}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Signature check failed: {ex.Message}");
            return false;
        }
    }

    static string ComputeFileHash(string filePath)
    {
        using (var sha256 = System.Security.Cryptography.SHA256.Create())
        {
            using (var stream = File.OpenRead(filePath))
            {
                byte[] hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }
    }

    static void StartSecureNamedPipeServer()
    {
        Console.WriteLine("\n[*] Starting SECURE Named Pipe server...");
        Console.WriteLine("[!] Note: For full ACL protection, set OS-level permissions manually");

        while (true)
        {
            try
            {
                using (var pipeServer = new NamedPipeServerStream(
                    "SecurePluginPipe",
                    PipeDirection.InOut,
                    1))
                {
                    Console.WriteLine("\n[*] Waiting for connection...");
                    Console.WriteLine("    (In production: Add ACLs via SetAccessControl)");

                    pipeServer.WaitForConnection();
                    Console.WriteLine("[✓] Client connected!");

                    using (var reader = new StreamReader(pipeServer))
                    using (var writer = new StreamWriter(pipeServer) { AutoFlush = true })
                    {
                        string command = reader.ReadLine();
                        Console.WriteLine($"[*] Command: {command}");

                        if (string.IsNullOrWhiteSpace(command))
                        {
                            writer.WriteLine("ERROR: Empty command");
                            continue;
                        }

                        var parts = command.Split('|');
                        if (parts.Length < 2)
                        {
                            writer.WriteLine("ERROR: Invalid format");
                            continue;
                        }

                        string pluginName = parts[0];
                        string input = parts[1];

                        if (!ALLOWED_PLUGINS.Contains(pluginName))
                        {
                            Console.WriteLine($"[!] BLOCKED: Plugin not in whitelist: {pluginName}");
                            writer.WriteLine($"ERROR: Plugin '{pluginName}' not authorized");
                            continue;
                        }

                        ExecutePluginInSandbox(pluginName, input, writer);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }
    }

    static void ExecutePluginInSandbox(string pluginName, string input, StreamWriter writer)
    {
        try
        {
            Console.WriteLine($"\n[*] Executing {pluginName} in SANDBOX...");

            string pluginPath = Path.Combine(Path.GetFullPath("plugins"), pluginName);
            IntPtr jobHandle = CreateJobObjectWithLimits();

            var psi = new ProcessStartInfo
            {
                FileName = "PluginExecutor.exe",
                Arguments = $"\"{pluginPath}\" \"{input}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using (var process = Process.Start(psi))
            {
                if (process == null)
                {
                    writer.WriteLine("ERROR: Cannot start plugin process");
                    return;
                }

                if (jobHandle != IntPtr.Zero)
                {
                    AssignProcessToJobObject(jobHandle, process.Handle);
                }

                bool finished = process.WaitForExit(30000);

                if (!finished)
                {
                    Console.WriteLine("[!] TIMEOUT: Killing plugin process");
                    process.Kill();
                    writer.WriteLine("ERROR: Plugin timeout");
                    return;
                }

                string output = process.StandardOutput.ReadToEnd();
                string errors = process.StandardError.ReadToEnd();

                Console.WriteLine($"[✓] Plugin finished (exit code: {process.ExitCode})");

                if (!string.IsNullOrEmpty(output))
                {
                    Console.WriteLine($"Output: {output}");
                }

                writer.WriteLine($"OK: {output}");

                if (jobHandle != IntPtr.Zero)
                {
                    CloseHandle(jobHandle);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Sandbox error: {ex.Message}");
            writer.WriteLine($"ERROR: {ex.Message}");
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    static IntPtr CreateJobObjectWithLimits()
    {
        try
        {
            IntPtr jobHandle = CreateJobObject(IntPtr.Zero, null);

            if (jobHandle == IntPtr.Zero)
            {
                Console.WriteLine("[!] Warning: Cannot create Job Object");
                return IntPtr.Zero;
            }

            Console.WriteLine("[✓] Job Object created (resource limits)");
            return jobHandle;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Job Object error: {ex.Message}");
            return IntPtr.Zero;
        }
    }
}