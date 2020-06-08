#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <minwindef.h> 

typedef void* PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
	ULONG      Length;
	BOOL       Initialized;
	LPVOID     SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY     InLoadOrderLinks;
	LIST_ENTRY     InMemoryOrderLinks;
	LIST_ENTRY     InInitializationOrderLinks;
	LPVOID         DllBase;
	LPVOID         EntryPoint;
	ULONG          SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB {
	BYTE                         InheritedAddressSpace;
	BYTE                         ReadImageFileExecOptions;
	BYTE                         BeingDebugged;

	BYTE                         _SYSTEM_DEPENDENT_01;
	LPVOID                       Mutant;
	LPVOID                       ImageBaseAddress;

	PPEB_LDR_DATA                Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	LPVOID                       SubSystemData;
	LPVOID                       ProcessHeap;
	LPVOID                       FastPebLock;
	LPVOID                       _SYSTEM_DEPENDENT_02;
	LPVOID                       _SYSTEM_DEPENDENT_03;
	LPVOID                       _SYSTEM_DEPENDENT_04;
	union {
		LPVOID                     KernelCallbackTable;
		LPVOID                     UserSharedInfoPtr;
	};
	DWORD                        SystemReserved;
	DWORD                        _SYSTEM_DEPENDENT_05;
	LPVOID                       _SYSTEM_DEPENDENT_06;
	LPVOID                       TlsExpansionCounter;
	LPVOID                       TlsBitmap;
	DWORD                        TlsBitmapBits[2];
	LPVOID                       ReadOnlySharedMemoryBase;
	LPVOID                       _SYSTEM_DEPENDENT_07;
	LPVOID                       ReadOnlyStaticServerData;
	LPVOID                       AnsiCodePageData;
	LPVOID                       OemCodePageData;
	LPVOID                       UnicodeCaseTableData;
	DWORD                        NumberOfProcessors;
	union {
		DWORD                      NtGlobalFlag;
		LPVOID                     dummy02;
	};
	LARGE_INTEGER                CriticalSectionTimeout;
	LPVOID                       HeapSegmentReserve;
	LPVOID                       HeapSegmentCommit;
	LPVOID                       HeapDeCommitTotalFreeThreshold;
	LPVOID                       HeapDeCommitFreeBlockThreshold;
	DWORD                        NumberOfHeaps;
	DWORD                        MaximumNumberOfHeaps;
	LPVOID                       ProcessHeaps;
	LPVOID                       GdiSharedHandleTable;
	LPVOID                       ProcessStarterHelper;
	LPVOID                       GdiDCAttributeList;
	LPVOID                       LoaderLock;
	DWORD                        OSMajorVersion;
	DWORD                        OSMinorVersion;
	WORD                         OSBuildNumber;
	WORD                         OSCSDVersion;
	DWORD                        OSPlatformId;
	DWORD                        ImageSubsystem;
	DWORD                        ImageSubsystemMajorVersion;
	LPVOID                       ImageSubsystemMinorVersion;
	union {
		LPVOID                     ImageProcessAffinityMask;
		LPVOID                     ActiveProcessAffinityMask;
	};
#ifdef _WIN64
	LPVOID                       GdiHandleBuffer[64];
#else
	LPVOID                       GdiHandleBuffer[32];
#endif  
	LPVOID                       PostProcessInitRoutine;
	LPVOID                       TlsExpansionBitmap;
	DWORD                        TlsExpansionBitmapBits[32];
	LPVOID                       SessionId;
	ULARGE_INTEGER               AppCompatFlags;
	ULARGE_INTEGER               AppCompatFlagsUser;
	LPVOID                       pShimData;
	LPVOID                       AppCompatInfo;
	PUNICODE_STRING              CSDVersion;
	LPVOID                       ActivationContextData;
	LPVOID                       ProcessAssemblyStorageMap;
	LPVOID                       SystemDefaultActivationContextData;
	LPVOID                       SystemAssemblyStorageMap;
	LPVOID                       MinimumStackCommit;
} PEB, * PPEB;

#define PROCESS_INSTRUMENTATION_CALLBACK (PROCESS_INFORMATION_CLASS)0x28

struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
	ULONG Version;
	ULONG Reserved;
	PVOID Callback;
};

struct _TEB_ACTIVE_FRAME;
struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	CHAR * FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	_TEB_ACTIVE_FRAME* Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;


typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
	_RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	_ACTIVATION_CONTEXT * ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK
{
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;


typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB
{
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB _ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	ULONG CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	VOID * SystemReserved1[54];
	LONG ExceptionCode;
	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR SpareBytes1[36];
	ULONG TxFsContext;
	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	PVOID GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG Win32ClientInfo[62];
	VOID * glDispatchTable[233];
	ULONG glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;
	ULONG LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];
	PVOID DeallocationStack;
	VOID * TlsSlots[64];
	LIST_ENTRY TlsLinks;
	PVOID Vdm;
	PVOID ReservedForNtRpc;
	VOID * DbgSsReserved[2];
	ULONG HardErrorMode;
	VOID * Instrumentation[9];
	GUID ActivityId;
	PVOID SubProcessTag;
	PVOID EtwLocalData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;
	UCHAR SpareBool0;
	UCHAR SpareBool1;
	UCHAR SpareBool2;
	UCHAR IdealProcessor;
	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG SoftPatchPtr1;
	PVOID ThreadPoolData;
	VOID * * TlsExpansionSlots;
	ULONG ImpersonationLocale;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	ULONG HeapVirtualAffinity;
	PVOID CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;
	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	WORD CrossTebFlags;
	ULONG SpareCrossTebBits : 16;
	WORD SameTebFlags;
	ULONG DbgSafeThunkCall : 1;
	ULONG DbgInDebugPrint : 1;
	ULONG DbgHasFiberData : 1;
	ULONG DbgSkipThreadAttach : 1;
	ULONG DbgWerInShipAssertCode : 1;
	ULONG DbgRanProcessInit : 1;
	ULONG DbgClonedThread : 1;
	ULONG DbgSuppressDebugMsg : 1;
	ULONG SpareSameTebBits : 8;
	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG ProcessRundown;
	UINT64 LastSwitchTime;
	UINT64 TotalSwitchOutTime;
	LARGE_INTEGER WaitReasonBitMap;
} TEB, *PTEB;

struct _TLS_ENTRY
{
	LIST_ENTRY TlsEntryLinks;
	IMAGE_TLS_DIRECTORY TlsDirectory;
	_LDR_DATA_TABLE_ENTRY *ModuleEntry;
};
