using System.Reflection;
// Тест: Опит да заредим unsigned assembly
// РИСК 1: Изпълнение на непроверен/зловреден код (Arbitrary Code Execution)

/// Какво представлява:
/// Хостът зарежда и изпълнява произволен .NET assembly без проверка на произхода,
/// целостта или дигиталния подпис. Атакуващ може да подмени легитимен plugin
/// с злонамерен код, който се изпълнява с правата на host процеса.
/// 
/// Предпоставки:
/// - Assembly.LoadFrom() без signature verification
/// - Plugins директорията е writable за обикновени потребители
/// - Липса на whitelist на разрешени assemblies
/// - Няма проверка на strong name или Authenticode signature
/// 
/// Концептуален пример:
/// 1. Легитимен plugin: LoggerPlugin.dll
/// 2. Атакуващ го замества с MaliciousPlugin.dll
/// 3. Host зарежда малициозния plugin без проверка
/// 4. Plugin изпълнява: Process.Start("cmd.exe", "/c reverse_shell.exe")
/// 5. Атакуващият получава remote shell с правата на сървиза
/// 
/// Въздействие:
/// - Пълен контрол над host процеса (Remote Code Execution)
/// - Изпълнение с привилегиите на сървиза (често SYSTEM)
/// - Достъп до всички ресурси и данни на host-а
/// - Възможност за persistence и lateral movement
class Risk1_UnverifiedCodeExecution
{
    public static bool DetectUnsignedAssembly(string assemblyPath)
    {
        try
        {
            var assembly = Assembly.LoadFrom(assemblyPath);

            byte[] publicKeyToken = assembly.GetName().GetPublicKeyToken();

            if (publicKeyToken == null || publicKeyToken.Length == 0)
            {
                Console.WriteLine($"[РИСК] Assembly '{assemblyPath}' няма strong name подпис!");
                return true;
            }

            Console.WriteLine($"[OK] Assembly '{assemblyPath}' е подписан: {BitConverter.ToString(publicKeyToken)}");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ГРЕШКА] Не може да се провери '{assemblyPath}': {ex.Message}");
            return true;
        }
    }

    public static bool DetectWritablePluginDirectory(string pluginDirectory)
    {
        try
        {
            var dirInfo = new DirectoryInfo(pluginDirectory);
            if (!dirInfo.Exists)
            {
                Console.WriteLine($"[ПРЕДУПРЕЖДЕНИЕ] Директорията '{pluginDirectory}' не съществува");
                return false;
            }

            string testFile = Path.Combine(pluginDirectory, "_test_write_" + Guid.NewGuid() + ".tmp");

            try
            {
                File.WriteAllText(testFile, "test");
                File.Delete(testFile);

                Console.WriteLine($"[РИСК] Директорията '{pluginDirectory}' е writable! Атакуващ може да подмени plugins!");
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"[OK] Директорията '{pluginDirectory}' е защитена срещу запис");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ГРЕШКА] {ex.Message}");
            return false;
        }
    }

    public static void TestUnverifiedLoading()
    {
        Console.WriteLine("\n--- ТЕСТ: Зареждане на непроверен assembly ---");

        string pluginDir = "plugins";
        if (!Directory.Exists(pluginDir))
            Directory.CreateDirectory(pluginDir);

        var dllFiles = Directory.GetFiles(pluginDir, "*.dll");

        foreach (var dll in dllFiles)
        {
            DetectUnsignedAssembly(dll);
        }

        DetectWritablePluginDirectory(pluginDir);
    }
}