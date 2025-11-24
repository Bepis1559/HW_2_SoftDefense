
using System.Diagnostics;

/// Какво представлява:
/// Зловреден или buggy plugin консумира прекалено много ресурси (CPU, RAM, disk,
/// threads) и причинява host процеса или цялата система да стане неотзивчива или
/// да падне (crash). Това е форма на Denial of Service (DoS) атака.
/// 
/// Предпоставки:
/// - Plugin има неограничен достъп до системни ресурси
/// - Липса на timeouts за plugin execution
/// - Няма memory limits или quotas
/// - Plugin може да създава безброй threads/processes
/// - Липса на rate limiting за plugin API calls
/// - Shared resource pools без isolation
/// 
/// Концептуален пример:
/// 1. CPU bomb: while(true) { Math.Sqrt(DateTime.Now.Ticks); } → 100% CPU
/// 2. Memory bomb: while(true) { list.Add(new byte[100MB]); } → OutOfMemoryException
/// 3. Thread bomb: for(i=0; i<100000; i++) new Thread(() => Sleep(Infinite)).Start()
/// 4. Disk bomb: while(true) { File.Write("temp_" + Guid.NewGuid(), 100MB); } → Disk full
/// 
/// Въздействие:
/// - Service downtime (availability impact)
/// - Cascade failures на други services на същия host
/// - System crash или instability
/// - Legitimate plugins не могат да работят
/// - DoS като distraction за друга атака

class Risk5_ResourceExhaustion
{
    public static bool DetectCPUExhaustion(Action pluginAction, int maxCpuMs = 1000)
    {
        Console.WriteLine("\n--- ТЕСТ: CPU exhaustion ---");

        try
        {
            var process = Process.GetCurrentProcess();
            var cpuBefore = process.TotalProcessorTime;
            var stopwatch = Stopwatch.StartNew();

            var task = Task.Run(pluginAction);
            bool completed = task.Wait(5000);

            stopwatch.Stop();
            var cpuAfter = process.TotalProcessorTime;
            var cpuUsed = (cpuAfter - cpuBefore).TotalMilliseconds;

            Console.WriteLine($"  CPU използван: {cpuUsed:F0} ms");
            Console.WriteLine($"  Wall time: {stopwatch.ElapsedMilliseconds} ms");

            if (!completed)
            {
                Console.WriteLine($"[РИСК] Plugin не завърши в разумно време (timeout)!");
                return true;
            }

            if (cpuUsed > maxCpuMs)
            {
                Console.WriteLine($"[РИСК] Plugin превиши CPU limit от {maxCpuMs} ms!");
                return true;
            }

            Console.WriteLine($"[OK] CPU usage в норма");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ГРЕШКА] {ex.Message}");
            return true;
        }
    }

    public static bool DetectMemoryExhaustion(Action pluginAction, long maxMemoryMB = 100)
    {
        Console.WriteLine("\n--- ТЕСТ: Memory exhaustion ---");

        try
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            long memBefore = GC.GetTotalMemory(false);

            try
            {
                pluginAction();
            }
            catch (OutOfMemoryException)
            {
                Console.WriteLine("[РИСК КРИТИЧЕН] Plugin причини OutOfMemoryException!");
                return true;
            }

            GC.Collect();
            long memAfter = GC.GetTotalMemory(true);
            long memUsedMB = (memAfter - memBefore) / (1024 * 1024);

            Console.WriteLine($"  Memory allocated: {memUsedMB} MB");

            if (memUsedMB > maxMemoryMB)
            {
                Console.WriteLine($"[РИСК] Plugin превиши memory limit от {maxMemoryMB} MB!");
                return true;
            }

            Console.WriteLine("[OK] Memory usage в норма");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ГРЕШКА] {ex.Message}");
            return true;
        }
    }

    public static bool DetectThreadBomb(Action pluginAction)
    {
        Console.WriteLine("\n--- ТЕСТ: Thread exhaustion ---");

        try
        {
            var process = Process.GetCurrentProcess();
            int threadsBefore = process.Threads.Count;

            pluginAction();

            System.Threading.Thread.Sleep(500);
            process.Refresh();
            int threadsAfter = process.Threads.Count;
            int threadsCreated = threadsAfter - threadsBefore;

            Console.WriteLine($"  Threads before: {threadsBefore}");
            Console.WriteLine($"  Threads after: {threadsAfter}");
            Console.WriteLine($"  Threads created: {threadsCreated}");

            if (threadsCreated > 50)
            {
                Console.WriteLine($"[РИСК] Plugin създаде прекалено много threads ({threadsCreated})!");
                return true;
            }

            Console.WriteLine("[OK] Thread creation в норма");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ГРЕШКА] {ex.Message}");
            return true;
        }
    }

    public static bool DetectDiskExhaustion(string testDirectory)
    {
        Console.WriteLine("\n--- ТЕСТ: Disk exhaustion ---");

        try
        {
            if (!Directory.Exists(testDirectory))
                Directory.CreateDirectory(testDirectory);

            var filesBefore = Directory.GetFiles(testDirectory).Length;
            var drive = new DriveInfo(Path.GetPathRoot(testDirectory));
            long spaceBeforeMB = drive.AvailableFreeSpace / (1024 * 1024);

            var filesAfter = Directory.GetFiles(testDirectory).Length;
            long spaceAfterMB = drive.AvailableFreeSpace / (1024 * 1024);
            long spaceUsedMB = spaceBeforeMB - spaceAfterMB;

            Console.WriteLine($"  Files created: {filesAfter - filesBefore}");
            Console.WriteLine($"  Disk space used: {spaceUsedMB} MB");

            foreach (var file in Directory.GetFiles(testDirectory, "_test_*"))
            {
                try { File.Delete(file); } catch { }
            }

            if (filesAfter - filesBefore > 1000)
            {
                Console.WriteLine($"[РИСК] Plugin създаде прекалено много файлове!");
                return true;
            }

            Console.WriteLine("[OK] Disk I/O в норма");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ГРЕШКА] {ex.Message}");
            return true;
        }
    }

    public static void RunAllResourceTests()
    {
        bool hasRisk = false;

        Console.WriteLine("\n=== Testing NORMAL plugin ===");
        Action normalPlugin = () =>
        {
            System.Threading.Thread.Sleep(100);
        };
        hasRisk |= DetectCPUExhaustion(normalPlugin);
        hasRisk |= DetectMemoryExhaustion(normalPlugin);

        Console.WriteLine("\n=== Testing CPU BOMB plugin ===");
        Action cpuBomb = () =>
        {
            var stopwatch = Stopwatch.StartNew();
            while (stopwatch.ElapsedMilliseconds < 2000)
            {
                Math.Sqrt(DateTime.Now.Ticks);
            }
        };
        hasRisk |= DetectCPUExhaustion(cpuBomb, maxCpuMs: 500);

        Console.WriteLine("\n=== Testing MEMORY BOMB plugin ===");
        Action memoryBomb = () =>
        {
            var leak = new List<byte[]>();
            for (int i = 0; i < 10; i++)
            {
                leak.Add(new byte[20 * 1024 * 1024]);
            }
        };
        hasRisk |= DetectMemoryExhaustion(memoryBomb, maxMemoryMB: 50);

        if (hasRisk)
        {
            Console.WriteLine("\n[ЗАКЛЮЧЕНИЕ] Открити са уязвимости за resource exhaustion!");
        }
    }
}
