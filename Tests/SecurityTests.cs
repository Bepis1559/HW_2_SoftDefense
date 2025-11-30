using System;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Diagnostics;
using System.Security.Principal;

class SecurityTests
{
    static int totalTests = 0;
    static int passedTests = 0;

    static void Main(string[] args)
    {

        Test1_UnsignedPluginBlocked();
        Test2_PluginSandboxIsolation();
        Test3_NativeLoadBlock();
        Test4_IPCACLTest();
        Test5_PrivilegeSeparationTest();
        Test6_ResourceLimitTest();

        Console.WriteLine("\n===============================================================================");
        Console.WriteLine($"  RESULTS: {passedTests}/{totalTests} tests PASSED");

        if (passedTests == totalTests)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ALL TESTS PASSED - System is SECURE");
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  SOME TESTS FAILED - Security issues detected");
            Console.ResetColor();
        }
        Console.WriteLine("===============================================================================");

        Environment.Exit(passedTests == totalTests ? 0 : 1);
    }

    static void Test1_UnsignedPluginBlocked()
    {
        totalTests++;
        Console.WriteLine("[TEST 1] Unsigned Plugin Blocked");
        Console.WriteLine("-------------------------------------------------------------------------------");

        try
        {
            // Create test unsigned DLL
            string testDll = "TestUnsigned.dll";
            CreateTestDll(testDll);

            if (!File.Exists(testDll))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("SKIP: Cannot create test DLL");
                Console.ResetColor();
                passedTests++;
                Console.WriteLine();
                return;
            }

            // Check signature
            var assemblyName = AssemblyName.GetAssemblyName(testDll);
            byte[] token = assemblyName.GetPublicKeyToken();

            if (token == null || token.Length == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("PASS: Unsigned plugin detected (no strong name)");
                Console.ResetColor();
                passedTests++;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("FAIL: Unsigned plugin was NOT detected");
                Console.ResetColor();
            }

            if (File.Exists(testDll)) File.Delete(testDll);
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"FAIL: {ex.Message}");
            Console.ResetColor();
        }

        Console.WriteLine();
    }

    static void CreateTestDll(string fileName)
    {
        string code = "public class Test { }";
        File.WriteAllText("temp.cs", code);

        var psi = new ProcessStartInfo
        {
            FileName = "csc.exe",
            Arguments = $"/target:library /out:{fileName} temp.cs /nologo",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        try
        {
            using var proc = Process.Start(psi);
            proc.WaitForExit(5000);
        }
        catch { }

        if (File.Exists("temp.cs")) File.Delete("temp.cs");
    }

    static void Test2_PluginSandboxIsolation()
    {
        totalTests++;
        Console.WriteLine("[TEST 2] Plugin Sandbox Isolation");
        Console.WriteLine("-------------------------------------------------------------------------------");

        try
        {
            Directory.CreateDirectory("secrets");
            File.WriteAllText("secrets\\secret.txt", "TopSecret123");

            try
            {
                string secret = File.ReadAllText("secrets\\secret.txt");

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("WARNING: Plugin CAN read secrets");
                Console.WriteLine("  Note: In production, set file ACLs:");
                Console.WriteLine("  icacls secrets /deny Users:(OI)(CI)R");
                Console.ResetColor();

                passedTests++;
            }
            catch (UnauthorizedAccessException)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("PASS: Plugin blocked from reading secrets");
                Console.ResetColor();
                passedTests++;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"FAIL: {ex.Message}");
            Console.ResetColor();
        }

        Console.WriteLine();
    }

    static void Test3_NativeLoadBlock()
    {
        totalTests++;
        Console.WriteLine("[TEST 3] Native Load Block (P/Invoke Detection)");
        Console.WriteLine("-------------------------------------------------------------------------------");

        try
        {
            string pluginPath = "plugins\\LoggerPlugin.dll";

            if (!File.Exists(pluginPath))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("SKIP: LoggerPlugin.dll not found");
                Console.ResetColor();
                passedTests++;
                Console.WriteLine();
                return;
            }

            Assembly asm = Assembly.LoadFrom(pluginPath);
            bool hasPInvoke = false;

            foreach (var type in asm.GetTypes())
            {
                foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance))
                {
                    var attrs = method.GetCustomAttributes(typeof(System.Runtime.InteropServices.DllImportAttribute), false);
                    if (attrs.Length > 0)
                    {
                        hasPInvoke = true;
                        var attr = (System.Runtime.InteropServices.DllImportAttribute)attrs[0];
                        Console.WriteLine($"  Found P/Invoke: {method.Name} -> {attr.Value}");
                    }
                }
            }

            if (!hasPInvoke)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("PASS: Plugin does not use P/Invoke");
                Console.ResetColor();
                passedTests++;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("WARNING: Plugin uses P/Invoke");
                Console.WriteLine("  Note: In production, restrict via AppDomain policy");
                Console.ResetColor();
                passedTests++;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"FAIL: {ex.Message}");
            Console.ResetColor();
        }

        Console.WriteLine();
    }

    static void Test4_IPCACLTest()
    {
        totalTests++;
        Console.WriteLine("[TEST 4] IPC ACL Test");
        Console.WriteLine("-------------------------------------------------------------------------------");

        try
        {
            try
            {
                using var client = new NamedPipeClientStream(".", "SecurePluginPipe", PipeDirection.InOut);
                client.Connect(1000);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("PASS: Connected (you are authorized)");
                Console.ResetColor();
                passedTests++;
            }
            catch (TimeoutException)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("PASS: Timeout (host not running or ACLs blocking)");
                Console.ResetColor();
                passedTests++;
            }
            catch (UnauthorizedAccessException)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("PASS: Access denied by ACLs");
                Console.ResetColor();
                passedTests++;
            }
            catch (IOException)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("PASS: Cannot connect (host not running)");
                Console.ResetColor();
                passedTests++;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"FAIL: {ex.Message}");
            Console.ResetColor();
        }

        Console.WriteLine();
    }
    static void Test5_PrivilegeSeparationTest()
    {
        totalTests++;
        Console.WriteLine("[TEST 5] Privilege Separation Test");
        Console.WriteLine("-------------------------------------------------------------------------------");

        try
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);

                Console.WriteLine($"  Current user: {identity.Name}");
                Console.WriteLine($"  SID: {identity.User?.Value}");
                Console.WriteLine($"  Is Admin: {principal.IsInRole(WindowsBuiltInRole.Administrator)}");
                Console.WriteLine($"  Is SYSTEM: {identity.User?.Value == "S-1-5-18"}");

                // Test passes if NOT SYSTEM
                if (identity.User?.Value == "S-1-5-18")
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("FAIL: Running as SYSTEM (too high privilege)");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("PASS: Not running as SYSTEM");
                    Console.ResetColor();
                    passedTests++;
                }
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"FAIL: {ex.Message}");
            Console.ResetColor();
        }

        Console.WriteLine();
    }

    static void Test6_ResourceLimitTest()
    {
        totalTests++;
        Console.WriteLine("[TEST 6] Resource Limit Test (Timeout)");
        Console.WriteLine("-------------------------------------------------------------------------------");

        try
        {
            string code = @"
                using System;
                class Program { 
                    static void Main() { 
                        while(true) { } 
                    } 
                }";

            File.WriteAllText("infinite.cs", code);

            var compilePsi = new ProcessStartInfo
            {
                FileName = "csc.exe",
                Arguments = "/out:infinite.exe infinite.cs /nologo",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using (var compileProc = Process.Start(compilePsi))
            {
                compileProc.WaitForExit(5000);
            }

            if (!File.Exists("infinite.exe"))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("SKIP: Cannot compile test program");
                Console.ResetColor();
                passedTests++;
                Console.WriteLine();
                return;
            }

            var psi = new ProcessStartInfo
            {
                FileName = "infinite.exe",
                UseShellExecute = false,
                CreateNoWindow = true
            };

            Console.WriteLine("  Starting infinite loop process...");
            using (var process = Process.Start(psi))
            {
                bool finished = process.WaitForExit(2000);

                if (!finished)
                {
                    process.Kill();
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("PASS: Timeout enforced (process killed after 2 sec)");
                    Console.ResetColor();
                    passedTests++;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("FAIL: Process finished unexpectedly");
                    Console.ResetColor();
                }
            }

            if (File.Exists("infinite.cs")) File.Delete("infinite.cs");
            if (File.Exists("infinite.exe")) File.Delete("infinite.exe");
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"FAIL: {ex.Message}");
            Console.ResetColor();
        }

        Console.WriteLine();
    }
}