
using System.Diagnostics;
using System.Security.Principal;

/// Какво представлява:
/// Plugin, изпълняващ се с високи привилегии (SYSTEM/Administrator), може да бъде
/// експлойтнат за да предостави тези привилегии на непривилегирован потребител
/// или процес. Атакуващ с low-privilege достъп може да получи SYSTEM shell.
/// 
/// Предпоставки:
/// - PluginHost работи като Windows Service с SYSTEM/Administrator account
/// - Plugins се изпълняват в същия процес (споделена памет)
/// - Plugin може да приема input от low-privilege потребители (IPC)
/// - Липса на impersonation или token restrictions
/// - Plugin има достъп до P/Invoke (native API calls)
/// 
/// Концептуален пример:
/// 1. PluginHost service работи като NT AUTHORITY\SYSTEM
/// 2. Приема команди през Named Pipe от обикновени потребители
/// 3. FileOperationsPlugin изпълнява: File.WriteAllText(userPath, userContent)
/// 4. Low-privilege потребител изпраща: "WriteFile|C:\Windows\System32\evil.dll|<backdoor>"
/// 5. Plugin с SYSTEM права записва файла успешно
/// 6. Атакуващ trigger-ва зареждането на evil.dll от друг system процес
/// 7. Или: Plugin използва P/Invoke за CreateProcessAsUser с SYSTEM token
/// 
/// Въздействие:
/// - Пълен контрол над системата (SYSTEM е highest privilege)
/// - Disable на security софтуер (antivirus, EDR)
/// - Модификация на критични системни файлове
/// - Persistent backdoor като system service
/// - Bypass на UAC и всички защити

class Risk3_PrivilegeEscalation
{
    public static bool DetectHighPrivilegeExecution()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            Console.WriteLine($"\n[INFO] Текущ потребител: {identity.Name}");

            bool isSystem = identity.User?.Value == "S-1-5-18"; // NT AUTHORITY\SYSTEM SID

            if (isSystem)
            {
                Console.WriteLine("[РИСК КРИТИЧЕН] Процесът работи като SYSTEM!");
                Console.WriteLine("  Plugins ще имат пълен контрол над системата!");
                return true;
            }

            var principal = new WindowsPrincipal(identity);
            bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

            if (isAdmin)
            {
                Console.WriteLine("[РИСК ВИСОК] Процесът работи с Administrator права!");
                Console.WriteLine("  Plugins могат да модифицират системата!");
                return true;
            }

            var tokenPrivileges = GetTokenPrivileges(identity.Token);
            if (tokenPrivileges.Any(p => p.Contains("SeDebugPrivilege") ||
                                          p.Contains("SeImpersonatePrivilege") ||
                                          p.Contains("SeTcbPrivilege")))
            {
                Console.WriteLine("[РИСК] Процесът има опасни привилегии:");
                foreach (var priv in tokenPrivileges)
                {
                    Console.WriteLine($"  - {priv}");
                }
                return true;
            }

            Console.WriteLine("[OK] Процесът работи с ограничени привилегии");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ГРЕШКА] {ex.Message}");
            return false;
        }
    }

    private static List<string> GetTokenPrivileges(IntPtr tokenHandle)
    {
        // За демонстрация връщаме празен списък
        return [];
    }

    // Тест: Опит да създадем процес с високи привилегии
    public static bool TestPrivilegeEscalation()
    {
        Console.WriteLine("\n--- ТЕСТ: Опит за privilege escalation ---");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c whoami",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (var process = Process.Start(psi))
            {
                process.WaitForExit(5000);
                string output = process.StandardOutput.ReadToEnd();

                Console.WriteLine($"[INFO] Създаден процес с identity: {output.Trim()}");

                if (output.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                    output.Contains("Administrator", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("[РИСК] Plugin може да създава високо привилегировани процеси!");
                    return true;
                }
            }

            string systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string testFile = Path.Combine(systemDir, "_privilege_test.tmp");

            try
            {
                File.WriteAllText(testFile, "test");
                File.Delete(testFile);

                Console.WriteLine($"[РИСК КРИТИЧЕН] Plugin може да записва в {systemDir}!");
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[OK] Plugin няма достъп до системни директории");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[INFO] Ограничения detectирани: {ex.Message}");
            return false;
        }
    }

    public static bool DetectWeakIPCPermissions(string pipeName)
    {
        Console.WriteLine($"\n--- ТЕСТ: Проверка на IPC ACLs за '{pipeName}' ---");

        // В реална имплементация проверяваме PipeSecurity ACLs

        Console.WriteLine("[INFO] За пълна проверка използвай PipeSecurity.GetAccessRules()");
        Console.WriteLine("       Pipe трябва да позволява connection САМО от Administrators");

        try
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

                if (!isAdmin)
                {
                    Console.WriteLine("[РИСК] Текущият low-privilege процес може да тества връзката");
                    Console.WriteLine("       Ако named pipe приема connection, това е уязвимост!");
                    return true;
                }
            }
        }
        catch { }

        return false;
    }
}