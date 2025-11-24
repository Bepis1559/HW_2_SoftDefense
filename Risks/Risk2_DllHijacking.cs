// РИСК 2: DLL/Assembly Hijacking


using System.Reflection;

/// Какво представлява:
/// Атакуващ поставя злонамерен assembly с име на легитимна зависимост в директория
/// с по-висок приоритет в search path. .NET/Windows зарежда злонамерения файл
/// вместо оригиналния, което води до изпълнение на arbitrary code.
/// 
/// Предпоставки:
/// - Assembly.LoadFrom() търси dependencies в текущата директория
/// - Plugins директорията е writable
/// - Не се използва LoadFromAssemblyPath с пълен път
/// - Липсва проверка на PublicKeyToken на зависимостите
/// - Plugins имат native dependencies (DllImport)
/// 
/// Концептуален пример:
/// 1. Plugin използва Newtonsoft.Json.dll
/// 2. Нормално .NET зарежда от GAC или application directory
/// 3. Атакуващ създава plugins\Newtonsoft.Json.dll с backdoor
/// 4. При зареждане на plugin, .NET търси зависимостта
/// 5. Намира я първо в plugins\ (текуща директория)
/// 6. Зарежда злонамерен версия
/// 7. Backdoor се изпълнява при static constructor
/// 
/// Въздействие:
/// - Stealth изпълнение на злонамерен код
/// - Persistence - зарежда се автоматично при всеки старт
/// - Bypass на application whitelisting
/// - Възможност за Man-in-the-Middle атаки

class Risk2_DllHijacking
{
    public static bool DetectSuspiciousAssemblies(string pluginDirectory)
    {
        try
        {
            var expectedPlugins = new HashSet<string>
                {
                    "LoggerPlugin.dll",
                    "DataProcessorPlugin.dll",
                    "ReportGeneratorPlugin.dll"
                };

            var dllFiles = Directory.GetFiles(pluginDirectory, "*.dll");
            bool suspiciousFound = false;

            foreach (var dll in dllFiles)
            {
                string fileName = Path.GetFileName(dll);

                if (!expectedPlugins.Contains(fileName))
                {
                    Console.WriteLine($"[РИСК] Неочакван assembly: '{fileName}'");
                    suspiciousFound = true;
                }

                try
                {
                    var assembly = Assembly.LoadFrom(dll);
                    var name = assembly.GetName();

                    if (IsSuspiciousSystemDll(fileName))
                    {
                        Console.WriteLine($"[РИСК КРИТИЧЕН] Възможен DLL hijack: '{fileName}' не трябва да е в plugins директорията!");
                        suspiciousFound = true;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ГРЕШКА] Не може да се зареди '{fileName}': {ex.Message}");
                }
            }

            if (!suspiciousFound)
            {
                Console.WriteLine("[OK] Няма подозрителни assemblies в plugins директорията");
            }

            return suspiciousFound;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ГРЕШКА] {ex.Message}");
            return false;
        }
    }

    private static bool IsSuspiciousSystemDll(string fileName)
    {
        var systemDllNames = new[]
        {
                "System.dll", "System.Core.dll", "System.Net.Http.dll",
                "mscorlib.dll", "netstandard.dll", "Newtonsoft.Json.dll",
                "System.Security.Cryptography.dll"
            };

        return systemDllNames.Any(name =>
            fileName.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    public static void MonitorAssemblyLoads()
    {
        Console.WriteLine("\n--- ТЕСТ: Мониторинг на assembly зареждания ---");

        AppDomain.CurrentDomain.AssemblyLoad += (sender, args) =>
        {
            var assembly = args.LoadedAssembly;
            string location = assembly.Location;

            if (!string.IsNullOrEmpty(location) &&
                location.Contains("plugins", StringComparison.OrdinalIgnoreCase))
            {
                var name = assembly.GetName();

                if (name.Name.StartsWith("System.") ||
                    name.Name.Equals("mscorlib") ||
                    name.Name.Equals("Newtonsoft.Json"))
                {
                    Console.WriteLine($"[РИСК КРИТИЧЕН] DLL Hijacking detected!");
                    Console.WriteLine($"  Assembly: {name.Name}");
                    Console.WriteLine($"  Location: {location}");
                    Console.WriteLine($"  Това НЕ трябва да се зарежда от plugins директорията!");
                }
            }
        };
    }
}