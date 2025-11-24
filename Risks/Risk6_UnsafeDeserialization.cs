using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

/// Какво представлява:
/// Host приема сериализирани данни (Binary, XML, JSON) от plugin или external source
/// и ги deserialized без валидация. Атакуващ може да inject malicious payload,
/// който при deserialization изпълнява arbitrary код (gadget chains).
/// 
/// Предпоставки:
/// - Използване на BinaryFormatter, NetDataContractSerializer или друг unsafe serializer
/// - IPC механизмът приема serialized objects
/// - Plugin може да изпраща crafted payloads към host
/// - Липса на type validation при deserialization
/// - Липса на input sanitization за plugin commands
/// - Host изпълнява команди с user input без validation
/// 
/// Концептуален пример:
/// 1. Host приема serialized command през Named Pipe:
///    var formatter = new BinaryFormatter();
///    var cmd = formatter.Deserialize(pipeStream);  // ОПАСНО!
/// 2. Атакуващ генерира malicious payload (ysoserial.net):
///    ObjectDataProvider gadget chain → Process.Start("cmd.exe")
/// 3. При deserialization се trigger-ва автоматично изпълнение на код
/// 4. Или command injection: "RunScript | cleanup.bat & net user hacker Pass123 /add"
/// 
/// Въздействие:
/// - Remote Code Execution (RCE) в host процеса
/// - Bypass на всички authentication/authorization
/// - Може да се trigger-не от remote attacker през IPC
/// - Често води до SYSTEM shell ако host е service
/// - Трудно за detection - изглежда като normal IPC traffic{
class Risk6_UnsafeDeserialization
{
    public static bool DetectUnsafeSerializers()
    {
        Console.WriteLine("\n--- ТЕСТ: Unsafe serialization patterns ---");


        try
        {
            var bfType = Type.GetType("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter, mscorlib");

            if (bfType != null)
            {
                Console.WriteLine("[ВНИМАНИЕ] BinaryFormatter type е наличен в runtime");
                Console.WriteLine("  В .NET Framework това е риск");
                Console.WriteLine("  В .NET 5+ има obsolete warning - което е добра защита");
                Console.WriteLine("  Препоръка: Използвай System.Text.Json вместо BinaryFormatter");

                var obsoleteAttr = bfType.GetCustomAttributes(typeof(ObsoleteAttribute), false);
                if (obsoleteAttr.Length > 0)
                {
                    Console.WriteLine("  ✓ BinaryFormatter е маркиран като [Obsolete] - добра защита!");
                    return false;
                }
                else
                {
                    Console.WriteLine("  ✗ BinaryFormatter НЕ е obsolete - РИСК!");
                    return true;
                }
            }
            else
            {
                Console.WriteLine("[OK] BinaryFormatter не е наличен в runtime");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[OK] BinaryFormatter проверката завърши: {ex.Message}");
            return false;
        }
    }

    public static bool DetectUnsafeSerializationInCode(string sourceCodeOrAssemblyPath)
    {
        Console.WriteLine("\n--- ТЕСТ: Static analysis за unsafe serialization ---");

        string[] dangerousPatterns = {
                "BinaryFormatter",
                "NetDataContractSerializer",
                "LosFormatter",
                "ObjectStateFormatter",
                "SoapFormatter"
            };

        Console.WriteLine("Проверка за опасни serialization APIs:");
        foreach (var pattern in dangerousPatterns)
        {
            Console.WriteLine($"  - {pattern} (RCE риск)");
        }

        Console.WriteLine("\n[INFO] За проверка на реален код:");
        Console.WriteLine("  1. Направи grep/search в source files:");
        Console.WriteLine("     grep -r \"BinaryFormatter\" *.cs");
        Console.WriteLine("  2. Използвай static analysis tools:");
        Console.WriteLine("     - SonarQube");
        Console.WriteLine("     - Microsoft Security Code Analysis");
        Console.WriteLine("  3. Runtime detection - log всички Deserialize calls");

        return false;
    }

    public static bool DetectCommandInjection(string userInput)
    {
        Console.WriteLine("\n--- ТЕСТ: Command injection ---");

        string[] injectionPatterns = {
                "&", "|", ";", "`", "$", "(", ")",
                ">", "<", "\n", "\r"
            };

        foreach (var pattern in injectionPatterns)
        {
            if (userInput.Contains(pattern))
            {
                Console.WriteLine($"[РИСК] Input съдържа опасен character: '{pattern}'");
                Console.WriteLine($"  Input: {userInput}");
                Console.WriteLine("  Това може да позволи command injection!");
                return true;
            }
        }

        Console.WriteLine("[OK] Input не съдържа injection patterns");
        return false;
    }

    public static bool SimulateDeserializationAttack()
    {
        Console.WriteLine("\n--- ТЕСТ: Deserialization attack simulation ---");

        try
        {

            string xmlPayload = @"
                <ObjectDataProvider MethodName='Start' 
                    ObjectType='System.Diagnostics.Process'>
                    <ObjectDataProvider.MethodParameters>
                        <string>cmd.exe</string>
                        <string>/c echo PWNED</string>
                    </ObjectDataProvider.MethodParameters>
                </ObjectDataProvider>";

            Console.WriteLine("[РИСК] Системата е уязвима ако deserialize такъв payload!");
            Console.WriteLine("  XML payload съдържа gadget chain за Process.Start");
            Console.WriteLine("  При deserialization с XamlReader → RCE!");

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[OK] Deserialization е защитен: {ex.Message}");
            return false;
        }
    }

    public static bool DetectSQLInjection(string userInput)
    {
        Console.WriteLine("\n--- ТЕСТ: SQL injection patterns ---");

        string[] sqlInjectionPatterns = {
                "'", "--", "/*", "*/", "xp_", "sp_",
                ";", "union", "select", "drop", "insert"
            };

        string lowerInput = userInput.ToLower();

        foreach (var pattern in sqlInjectionPatterns)
        {
            if (lowerInput.Contains(pattern))
            {
                Console.WriteLine($"[РИСК] Input съдържа SQL injection pattern: '{pattern}'");
                Console.WriteLine($"  Input: {userInput}");
                Console.WriteLine("  Използвай parameterized queries!");
                return true;
            }
        }

        Console.WriteLine("[OK] Input не съдържа SQL injection patterns");
        return false;
    }

    public static void RunAllInjectionTests()
    {
        bool hasRisk = false;

        hasRisk |= DetectUnsafeSerializers();

        DetectUnsafeSerializationInCode("PluginHost.cs");

        string[] testInputs = {
                "cleanup.bat",  // Safe
                "cleanup.bat & whoami",  // Command injection
                "test | calc.exe",  // Pipe injection
                "file.txt; rm -rf /"  // Shell injection
            };

        foreach (var input in testInputs)
        {
            hasRisk |= DetectCommandInjection(input);
        }

        string[] sqlTestInputs = {
                "John",  // Safe
                "admin' OR '1'='1",  // SQL injection
                "'; DROP TABLE users; --"  // SQL injection
            };

        foreach (var input in sqlTestInputs)
        {
            hasRisk |= DetectSQLInjection(input);
        }

        hasRisk |= SimulateDeserializationAttack();

        if (hasRisk)
        {
            Console.WriteLine("\n[ЗАКЛЮЧЕНИЕ] Открити са injection уязвимости!");
            Console.WriteLine("\nЗАЩИТА:");
            Console.WriteLine("  • НЕ използвай BinaryFormatter (obsolete и опасен)");
            Console.WriteLine("  • Използвай System.Text.Json или protobuf");
            Console.WriteLine("  • Validate и sanitize всички inputs");
            Console.WriteLine("  • Използвай parameterized queries за SQL");
            Console.WriteLine("  • Whitelist allowed characters/commands");
        }
        else
        {
            Console.WriteLine("\n[OK] Не са открити критични injection уязвимости");
        }
    }

}

