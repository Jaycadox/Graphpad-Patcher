using Reloaded.Memory.Sigscan;
using System.Diagnostics;
using System.Runtime.InteropServices;

[DllImport("kernel32.dll")]
static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
[DllImport("kernel32.dll")]
static extern uint SuspendThread(IntPtr hThread);
[DllImport("kernel32.dll")]
static extern int ResumeThread(IntPtr hThread);
[DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
static extern bool CloseHandle(IntPtr handle);

[DllImport("kernel32.dll", SetLastError = true)]
static extern bool WriteProcessMemory(
    IntPtr hProcess,
    IntPtr lpBaseAddress,
    byte[] lpBuffer,
    Int32 nSize,
    out IntPtr lpNumberOfBytesWritten);

void SuspendProcess(int pid)
{
    var process = Process.GetProcessById(pid); // throws exception if process does not exist

    foreach (ProcessThread pT in process.Threads)
    {
        IntPtr pOpenThread = OpenThread(ThreadAccess.SuspendResume, false, (uint)pT.Id);

        if (pOpenThread == IntPtr.Zero)
        {
            continue;
        }

        SuspendThread(pOpenThread);

        CloseHandle(pOpenThread);
    }
}

static void ResumeProcess(int pid)
{
    var process = Process.GetProcessById(pid);

    if (process.ProcessName == string.Empty)
        return;

    foreach (ProcessThread pT in process.Threads)
    {
        var pOpenThread = OpenThread(ThreadAccess.SuspendResume, false, (uint)pT.Id);

        if (pOpenThread == IntPtr.Zero)
        {
            continue;
        }

        var suspendCount = 0;
        do
        {
            suspendCount = ResumeThread(pOpenThread);
        } while (suspendCount > 0);

        CloseHandle(pOpenThread);
    }
}

Process?[] procList = Process.GetProcessesByName("prism");
Process? proc;
var keepAlive = false;
if (procList.Length == 0)
{
    Console.WriteLine("INFO -- Running GraphPad Prism...");
    proc = Process.Start(new ProcessStartInfo
    {
        FileName= "C:\\Program Files\\GraphPad\\Prism 10\\prism.exe"
    });
    Thread.Sleep(30);
}
else
{
    keepAlive = true;
    proc = procList[0];
}

if (proc is null)
{
    Console.WriteLine("INFO -- Failed to run/find GraphPad Prism");
    return;
}

var handle = proc.Handle;
var moduleBase = proc.MainModule!.BaseAddress;
var scanner = new Scanner(proc, proc.MainModule);

#if DEBUG
Console.WriteLine($"DEBUG -- 'prism.exe' -- Handle = 0x{handle:X}, Module base = 0x{moduleBase:X}");
#endif

var patches = new List<(string sig, byte[] data, int offset)>();

void AddPatch(string sig, byte[] data, int sigOffset = 0)
{
    patches.Add((sig, data, sigOffset));
}

void ApplyPatches()
{
    SuspendProcess(proc.Id);
    var num = 0;
    var locations = scanner.FindPatterns(patches.Select(x => x.sig).ToList());
    var results = locations.Select(x => x.Offset)
        .Zip(patches, (loc, patch) =>
    {
        var current = num++;
        if (loc == -1)
        {
            return false;
        }

        WriteProcessMemory(handle, moduleBase + loc + patch.offset, patch.data, patch.data.Length, out nint i);
        return i == patch.data.Length;
    });

    var failedPatches = results.Select((x, i) => (x, i)).Where(x => !x.x).Select(x => x.i).ToList();
    if (failedPatches.Count != 0)
    {
        Console.WriteLine("ERROR -- Failed patches: " + string.Join(", ", failedPatches));
    }

    ResumeProcess(proc.Id);
    var score = (results.Count(x => x), patches.Count);
    Console.WriteLine($"INFO -- 'prism.exe' -- Applied {score.Item1}/{score.Item2} patches.");
    if (score.Item1 != score.Item2)
    {
        Console.WriteLine("-- PATCH FAILED --");
        Console.WriteLine("Could not patch all patterns. Either the executable is already patched, or it has updated.");
        keepAlive = true;
    }

    if (keepAlive)
    {
        Console.ReadKey();
    }

}

AddPatch(
    "0F 84 ?? ?? ?? ?? 33 D2 41 B8 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 41 B9",
    new byte[] { 0xE9, 0xFB, 0x00 }
);

AddPatch(
    "0F 84 ?? ?? ?? ?? 8B 44 24 7C 3D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 33 D2 44 8D 40 3C 48 8D 8D",
    new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }
);

AddPatch(
    "0F 85 ?? ?? ?? ?? 33 D2 44 8D 40 3C 48 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 D2 41 B8",
    new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }
);

AddPatch(
    "0F 84 ?? ?? ?? ?? 41 B9 ?? ?? ?? ?? 4C 8D 85 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 4C 8D 85",
    new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }
);

AddPatch(
    "0F 84 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 4C 8D 85 ?? ?? ?? ?? 4C 2B C0 0F B6 10 42 0F B6 0C 00 2B D1",
    new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }
);

AddPatch(
    "0F 85 ?? ?? ?? ?? 41 8B F4 4D 85 F6 74 4E 8B 9D ?? ?? ?? ?? 85 DB 7E 44 66 45 89 26 40 88 B5",
    new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }
);

AddPatch(
    "BE ?? ?? ?? ?? 4C 39 64 24 ?? 74 0B 48 8D 4C 24 ?? FF 15",
    new byte[] { 0x0 },
    1
);

AddPatch(
    "89 44 24 30 48 8B 84 24 ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 84 24 ?? ?? ?? ?? 48 89 44 24 ?? E8 ?? ?? ?? ?? 48 83 C4 68 C3",
    new byte[] { 0xB8, 0xC8, 0x00, 0x00, 0x00, 0xC3 },
    39
);

AddPatch(
    "74 68 48 8B 4F 70 E8 ?? ?? ?? ?? 8B D8 44 8B C8 45 8B C7",
    new byte[] { 0x90, 0x90 }
);

AddPatch(
    "74 1B 32 DB EB 19 45 33 C9 45 8B C7 48 8D 15 ?? ?? ?? ?? 41 8D 49 02 E8",
    new byte[] { 0x90, 0x90 }
);

AddPatch(
    "48 8B 01 8B 48 08 83 F9 08 77 10 B8 ?? ?? ?? ?? 0F A3 C8 73 06 B8 ?? ?? ?? ?? C3 33 C0",
    new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 },
    27
);

AddPatch(
    "33 C0 39 42 08 0F 94 C0 C3",
    new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90 }
);

AddPatch(
    "48 8B 01 83 78 08 00 75 0F 83 B8 ?? ?? ?? ?? ?? 74 06 B8 ?? ?? ?? ?? C3 33 C0",
    new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 },
    24
);

AddPatch(
    "E8 ?? ?? ?? ?? 41 8B 86 ?? ?? ?? ?? EB 02 33 C0 48 8B 8C 24 ?? ?? ?? ?? 48 33 CC E8 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 41 5F 41 5E 5D C3",
    new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 },
    44
);

ApplyPatches();

[Flags]
internal enum ThreadAccess : int
{
    SuspendResume = (0x0002),
}