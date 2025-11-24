6-те документирани риска
1. Изпълнение на непроверен код (Arbitrary Code Execution)

Описание: Зареждане на unverified assemblies без signature check
Откриване: Проверка на strong name подписи, writable директории

2. DLL/Assembly Hijacking

Описание: Подмяна на системни DLLs в plugins директорията
Откриване: Whitelist validation, PublicKeyToken проверки, assembly load monitoring

3. Privilege Escalation

Описание: Plugin получава SYSTEM/Admin привилегии от host
Откриване: Token analysis, процес привилегии проверка, IPC ACL audit

4. Изтичане на чувствителни данни (Data Leakage)

Описание: Plugin извлича secrets чрез reflection или file access
Откриване: Secrets file access test, reflection attack detection, network monitoring

5. Resource Exhaustion / DoS

Описание: CPU/Memory/Thread/Disk bombing
Откриване: Resource monitoring (CPU, Memory), timeouts, thread counting

6. Unsafe Deserialization / Injection

Описание: RCE чрез BinaryFormatter, command injection
Откриване: Unsafe serializer detection, injection pattern matching