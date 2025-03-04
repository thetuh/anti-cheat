#pragma once

#include <cstdint>

struct reloc_entry
{
	std::uint16_t offset : 12;
	std::uint16_t type : 4;
};

#ifdef _WIN64
struct PEB_LDR_DATA
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	VOID* SsHandle;                                                         //0x8
	struct _LIST_ENTRY InLoadOrderModuleList;                               //0xc
	struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x14
	struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x1c
	VOID* EntryInProgress;                                                  //0x24
	UCHAR ShutdownInProgress;                                               //0x28
	VOID* ShutdownThreadId;                                                 //0x2c
}; static_assert( sizeof( PEB_LDR_DATA ) == 0x58 );

struct UNICODE_STRING
{
	USHORT Length;                                                          //0x0
	USHORT MaximumLength;                                                   //0x2
	WCHAR* Buffer;                                                          //0x4
}; static_assert ( sizeof( UNICODE_STRING ) == 0x10 );

struct STRING
{
	USHORT Length;                                                          //0x0
	USHORT MaximumLength;                                                   //0x2
	CHAR* Buffer;                                                           //0x4
}; static_assert ( sizeof( STRING ) == 0x10 );

struct CURDIR
{
	struct UNICODE_STRING DosPath;                                         //0x0
	VOID* Handle;                                                           //0x8
}; static_assert ( sizeof( CURDIR ) == 0x18 );

struct RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;                                                           //0x0
	USHORT Length;                                                          //0x2
	ULONG TimeStamp;                                                        //0x4
	struct STRING DosPath;                                                 //0x8
}; static_assert ( sizeof( RTL_DRIVE_LETTER_CURDIR ) == 0x18 );

struct RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;                                                    //0x0
	ULONG Length;                                                           //0x4
	ULONG Flags;                                                            //0x8
	ULONG DebugFlags;                                                       //0xc
	VOID* ConsoleHandle;                                                    //0x10
	ULONG ConsoleFlags;                                                     //0x14
	VOID* StandardInput;                                                    //0x18
	VOID* StandardOutput;                                                   //0x1c
	VOID* StandardError;                                                    //0x20
	struct CURDIR CurrentDirectory;                                        //0x24
	struct UNICODE_STRING DllPath;                                         //0x30
	struct UNICODE_STRING ImagePathName;                                   //0x38
	struct UNICODE_STRING CommandLine;                                     //0x40
	VOID* Environment;                                                      //0x48
	ULONG StartingX;                                                        //0x4c
	ULONG StartingY;                                                        //0x50
	ULONG CountX;                                                           //0x54
	ULONG CountY;                                                           //0x58
	ULONG CountCharsX;                                                      //0x5c
	ULONG CountCharsY;                                                      //0x60
	ULONG FillAttribute;                                                    //0x64
	ULONG WindowFlags;                                                      //0x68
	ULONG ShowWindowFlags;                                                  //0x6c
	struct UNICODE_STRING WindowTitle;                                     //0x70
	struct UNICODE_STRING DesktopInfo;                                     //0x78
	struct UNICODE_STRING ShellInfo;                                       //0x80
	struct UNICODE_STRING RuntimeData;                                     //0x88
	struct RTL_DRIVE_LETTER_CURDIR CurrentDirectores[ 32 ];                  //0x90
	ULONGLONG EnvironmentSize;                                              //0x290
	ULONGLONG EnvironmentVersion;                                           //0x294
	VOID* PackageDependencyData;                                            //0x298
	ULONG ProcessGroupId;                                                   //0x29c
	ULONG LoaderThreads;                                                    //0x2a0
	struct UNICODE_STRING RedirectionDllName;                              //0x2a4
	struct UNICODE_STRING HeapPartitionName;                               //0x2ac
	ULONGLONG* DefaultThreadpoolCpuSetMasks;                                //0x2b4
	ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x2b8
	ULONG DefaultThreadpoolThreadMaximum;                                   //0x2bc
}; static_assert ( sizeof( RTL_USER_PROCESS_PARAMETERS ) == 0x440 );

struct RTL_BALANCED_NODE
{
	union
	{
		struct RTL_BALANCED_NODE* Children[ 2 ];                             //0x0
		struct
		{
			struct RTL_BALANCED_NODE* Left;                                //0x0
			struct RTL_BALANCED_NODE* Right;                               //0x8
		};
	};
	union
	{
		struct
		{
			UCHAR Red : 1;                                                    //0x10
			UCHAR Balance : 2;                                                //0x10
		};
		ULONGLONG ParentValue;                                              //0x10
	};
}; static_assert ( sizeof( RTL_BALANCED_NODE ) == 0x18 );

struct _PEB
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	UCHAR Padding0[ 4 ];                                                      //0x4
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	struct PEB_LDR_DATA* Ldr;                                              //0x18
	struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
	VOID* SubSystemData;                                                    //0x28
	VOID* ProcessHeap;                                                      //0x30
	struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
	union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
	VOID* IFEOKey;                                                          //0x48
	union
	{
		ULONG CrossProcessFlags;                                            //0x50
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x50
			ULONG ProcessInitializing : 1;                                    //0x50
			ULONG ProcessUsingVEH : 1;                                        //0x50
			ULONG ProcessUsingVCH : 1;                                        //0x50
			ULONG ProcessUsingFTH : 1;                                        //0x50
			ULONG ProcessPreviouslyThrottled : 1;                             //0x50
			ULONG ProcessCurrentlyThrottled : 1;                              //0x50
			ULONG ProcessImagesHotPatched : 1;                                //0x50
			ULONG ReservedBits0 : 24;                                         //0x50
		};
	};
	UCHAR Padding1[ 4 ];                                                      //0x54
	union
	{
		VOID* KernelCallbackTable;                                          //0x58
		VOID* UserSharedInfoPtr;                                            //0x58
	};
	ULONG SystemReserved;                                                   //0x60
	ULONG AtlThunkSListPtr32;                                               //0x64
	VOID* ApiSetMap;                                                        //0x68
	ULONG TlsExpansionCounter;                                              //0x70
	UCHAR Padding2[ 4 ];                                                      //0x74
	VOID* TlsBitmap;                                                        //0x78
	ULONG TlsBitmapBits[ 2 ];                                                 //0x80
	VOID* ReadOnlySharedMemoryBase;                                         //0x88
	VOID* SharedData;                                                       //0x90
	VOID** ReadOnlyStaticServerData;                                        //0x98
	VOID* AnsiCodePageData;                                                 //0xa0
	VOID* OemCodePageData;                                                  //0xa8
	VOID* UnicodeCaseTableData;                                             //0xb0
	ULONG NumberOfProcessors;                                               //0xb8
	ULONG NtGlobalFlag;                                                     //0xbc
	union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
	ULONGLONG HeapSegmentReserve;                                           //0xc8
	ULONGLONG HeapSegmentCommit;                                            //0xd0
	ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
	ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
	ULONG NumberOfHeaps;                                                    //0xe8
	ULONG MaximumNumberOfHeaps;                                             //0xec
	VOID** ProcessHeaps;                                                    //0xf0
	VOID* GdiSharedHandleTable;                                             //0xf8
	VOID* ProcessStarterHelper;                                             //0x100
	ULONG GdiDCAttributeList;                                               //0x108
	UCHAR Padding3[ 4 ];                                                      //0x10c
	struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
	ULONG OSMajorVersion;                                                   //0x118
	ULONG OSMinorVersion;                                                   //0x11c
	USHORT OSBuildNumber;                                                   //0x120
	USHORT OSCSDVersion;                                                    //0x122
	ULONG OSPlatformId;                                                     //0x124
	ULONG ImageSubsystem;                                                   //0x128
	ULONG ImageSubsystemMajorVersion;                                       //0x12c
	ULONG ImageSubsystemMinorVersion;                                       //0x130
	UCHAR Padding4[ 4 ];                                                      //0x134
	ULONGLONG ActiveProcessAffinityMask;                                    //0x138
	ULONG GdiHandleBuffer[ 60 ];                                              //0x140
	VOID( *PostProcessInitRoutine )( );                                       //0x230
	VOID* TlsExpansionBitmap;                                               //0x238
	ULONG TlsExpansionBitmapBits[ 32 ];                                       //0x240
	ULONG SessionId;                                                        //0x2c0
	UCHAR Padding5[ 4 ];                                                      //0x2c4
	union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
	union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
	VOID* pShimData;                                                        //0x2d8
	VOID* AppCompatInfo;                                                    //0x2e0
	struct UNICODE_STRING CSDVersion;                                      //0x2e8
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
	ULONGLONG MinimumStackCommit;                                           //0x318
	VOID* SparePointers[ 4 ];                                                 //0x320
	ULONG SpareUlongs[ 5 ];                                                   //0x340
	VOID* WerRegistrationData;                                              //0x358
	VOID* WerShipAssertPtr;                                                 //0x360
	VOID* pUnused;                                                          //0x368
	VOID* pImageHeaderHash;                                                 //0x370
	union
	{
		ULONG TracingFlags;                                                 //0x378
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x378
			ULONG CritSecTracingEnabled : 1;                                  //0x378
			ULONG LibLoaderTracingEnabled : 1;                                //0x378
			ULONG SpareTracingBits : 29;                                      //0x378
		};
	};
	UCHAR Padding6[ 4 ];                                                      //0x37c
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
	ULONGLONG TppWorkerpListLock;                                           //0x388
	struct _LIST_ENTRY TppWorkerpList;                                      //0x390
	VOID* WaitOnAddressHashTable[ 128 ];                                      //0x3a0
	VOID* TelemetryCoverageHeader;                                          //0x7a0
	ULONG CloudFileFlags;                                                   //0x7a8
	ULONG CloudFileDiagFlags;                                               //0x7ac
	CHAR PlaceholderCompatibilityMode;                                      //0x7b0
	CHAR PlaceholderCompatibilityModeReserved[ 7 ];                           //0x7b1
	struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x7b8
	union
	{
		ULONG LeapSecondFlags;                                              //0x7c0
		struct
		{
			ULONG SixtySecondEnabled : 1;                                     //0x7c0
			ULONG Reserved : 31;                                              //0x7c0
		};
	};
	ULONG NtGlobalFlag2;                                                    //0x7c4
}; static_assert ( sizeof( _PEB ) == 0x7c8 );

struct LDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	struct UNICODE_STRING FullDllName;                                     //0x48
	struct UNICODE_STRING BaseDllName;                                     //0x58
	union
	{
		UCHAR FlagGroup[ 4 ];                                                 //0x68
		ULONG Flags;                                                        //0x68
		struct
		{
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG LoadConfigProcessed : 1;                                    //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ProtectDelayLoad : 1;                                       //0x68
			ULONG ReservedFlags3 : 2;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ChpeImage : 1;                                              //0x68
			ULONG ReservedFlags5 : 2;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	struct _LIST_ENTRY HashLinks;                                           //0x70
	ULONG TimeDateStamp;                                                    //0x80
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	VOID* Lock;                                                             //0x90
	struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
	struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
	struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
	VOID* ParentDllBase;                                                    //0xb8
	VOID* SwitchBackContext;                                                //0xc0
	struct RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
	struct RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	union _LARGE_INTEGER LoadTime;                                          //0x100
	ULONG BaseNameHashValue;                                                //0x108
	enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
	ULONG DependentLoadFlags;                                               //0x118
	UCHAR SigningLevel;                                                     //0x11c
}; static_assert( sizeof( LDR_DATA_TABLE_ENTRY ) == 0x120 );
#else
struct PEB_LDR_DATA
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	VOID* SsHandle;                                                         //0x8
	struct _LIST_ENTRY InLoadOrderModuleList;                               //0xc
	struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x14
	struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x1c
	VOID* EntryInProgress;                                                  //0x24
	UCHAR ShutdownInProgress;                                               //0x28
	VOID* ShutdownThreadId;                                                 //0x2c
}; static_assert( sizeof( PEB_LDR_DATA ) == 0x30 );

struct UNICODE_STRING
{
	USHORT Length;                                                          //0x0
	USHORT MaximumLength;                                                   //0x2
	WCHAR* Buffer;                                                          //0x4
}; static_assert ( sizeof( UNICODE_STRING ) == 0x8 );

struct STRING
{
	USHORT Length;                                                          //0x0
	USHORT MaximumLength;                                                   //0x2
	CHAR* Buffer;                                                           //0x4
}; static_assert ( sizeof( STRING ) == 0x8 );

struct CURDIR
{
	struct UNICODE_STRING DosPath;                                         //0x0
	VOID* Handle;                                                           //0x8
}; static_assert ( sizeof( CURDIR ) == 0xc );

struct RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;                                                           //0x0
	USHORT Length;                                                          //0x2
	ULONG TimeStamp;                                                        //0x4
	struct STRING DosPath;                                                 //0x8
}; static_assert ( sizeof( RTL_DRIVE_LETTER_CURDIR ) == 0x10 );

struct RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;                                                    //0x0
	ULONG Length;                                                           //0x4
	ULONG Flags;                                                            //0x8
	ULONG DebugFlags;                                                       //0xc
	VOID* ConsoleHandle;                                                    //0x10
	ULONG ConsoleFlags;                                                     //0x14
	VOID* StandardInput;                                                    //0x18
	VOID* StandardOutput;                                                   //0x1c
	VOID* StandardError;                                                    //0x20
	struct CURDIR CurrentDirectory;                                        //0x24
	struct UNICODE_STRING DllPath;                                         //0x30
	struct UNICODE_STRING ImagePathName;                                   //0x38
	struct UNICODE_STRING CommandLine;                                     //0x40
	VOID* Environment;                                                      //0x48
	ULONG StartingX;                                                        //0x4c
	ULONG StartingY;                                                        //0x50
	ULONG CountX;                                                           //0x54
	ULONG CountY;                                                           //0x58
	ULONG CountCharsX;                                                      //0x5c
	ULONG CountCharsY;                                                      //0x60
	ULONG FillAttribute;                                                    //0x64
	ULONG WindowFlags;                                                      //0x68
	ULONG ShowWindowFlags;                                                  //0x6c
	struct UNICODE_STRING WindowTitle;                                     //0x70
	struct UNICODE_STRING DesktopInfo;                                     //0x78
	struct UNICODE_STRING ShellInfo;                                       //0x80
	struct UNICODE_STRING RuntimeData;                                     //0x88
	struct RTL_DRIVE_LETTER_CURDIR CurrentDirectores[ 32 ];                  //0x90
	ULONG EnvironmentSize;                                                  //0x290
	ULONG EnvironmentVersion;                                               //0x294
	VOID* PackageDependencyData;                                            //0x298
	ULONG ProcessGroupId;                                                   //0x29c
	ULONG LoaderThreads;                                                    //0x2a0
	struct UNICODE_STRING RedirectionDllName;                              //0x2a4
	struct UNICODE_STRING HeapPartitionName;                               //0x2ac
	ULONGLONG* DefaultThreadpoolCpuSetMasks;                                //0x2b4
	ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x2b8
	ULONG DefaultThreadpoolThreadMaximum;                                   //0x2bc
}; static_assert ( sizeof( RTL_USER_PROCESS_PARAMETERS ) == 0x2c0 );

struct RTL_BALANCED_NODE
{
	union
	{
		struct RTL_BALANCED_NODE* Children[ 2 ];                             //0x0
		struct
		{
			struct RTL_BALANCED_NODE* Left;                                //0x0
			struct RTL_BALANCED_NODE* Right;                               //0x4
		};
	};
	union
	{
		struct
		{
			UCHAR Red : 1;                                                    //0x8
			UCHAR Balance : 2;                                                //0x8
		};
		ULONG ParentValue;                                                  //0x8
	};
}; static_assert ( sizeof( RTL_BALANCED_NODE ) == 0xc );

struct _PEB
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	VOID* Mutant;                                                           //0x4
	VOID* ImageBaseAddress;                                                 //0x8
	struct PEB_LDR_DATA* Ldr;                                              //0xc
	struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x10
	VOID* SubSystemData;                                                    //0x14
	VOID* ProcessHeap;                                                      //0x18
	struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x1c
	union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x20
	VOID* IFEOKey;                                                          //0x24
	union
	{
		ULONG CrossProcessFlags;                                            //0x28
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x28
			ULONG ProcessInitializing : 1;                                    //0x28
			ULONG ProcessUsingVEH : 1;                                        //0x28
			ULONG ProcessUsingVCH : 1;                                        //0x28
			ULONG ProcessUsingFTH : 1;                                        //0x28
			ULONG ProcessPreviouslyThrottled : 1;                             //0x28
			ULONG ProcessCurrentlyThrottled : 1;                              //0x28
			ULONG ProcessImagesHotPatched : 1;                                //0x28
			ULONG ReservedBits0 : 24;                                         //0x28
		};
	};
	union
	{
		VOID* KernelCallbackTable;                                          //0x2c
		VOID* UserSharedInfoPtr;                                            //0x2c
	};
	ULONG SystemReserved;                                                   //0x30
	union _SLIST_HEADER* volatile AtlThunkSListPtr32;                       //0x34
	VOID* ApiSetMap;                                                        //0x38
	ULONG TlsExpansionCounter;                                              //0x3c
	VOID* TlsBitmap;                                                        //0x40
	ULONG TlsBitmapBits[ 2 ];                                                 //0x44
	VOID* ReadOnlySharedMemoryBase;                                         //0x4c
	VOID* SharedData;                                                       //0x50
	VOID** ReadOnlyStaticServerData;                                        //0x54
	VOID* AnsiCodePageData;                                                 //0x58
	VOID* OemCodePageData;                                                  //0x5c
	VOID* UnicodeCaseTableData;                                             //0x60
	ULONG NumberOfProcessors;                                               //0x64
	ULONG NtGlobalFlag;                                                     //0x68
	union _LARGE_INTEGER CriticalSectionTimeout;                            //0x70
	ULONG HeapSegmentReserve;                                               //0x78
	ULONG HeapSegmentCommit;                                                //0x7c
	ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
	ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
	ULONG NumberOfHeaps;                                                    //0x88
	ULONG MaximumNumberOfHeaps;                                             //0x8c
	VOID** ProcessHeaps;                                                    //0x90
	VOID* GdiSharedHandleTable;                                             //0x94
	VOID* ProcessStarterHelper;                                             //0x98
	ULONG GdiDCAttributeList;                                               //0x9c
	struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0xa0
	ULONG OSMajorVersion;                                                   //0xa4
	ULONG OSMinorVersion;                                                   //0xa8
	USHORT OSBuildNumber;                                                   //0xac
	USHORT OSCSDVersion;                                                    //0xae
	ULONG OSPlatformId;                                                     //0xb0
	ULONG ImageSubsystem;                                                   //0xb4
	ULONG ImageSubsystemMajorVersion;                                       //0xb8
	ULONG ImageSubsystemMinorVersion;                                       //0xbc
	ULONG ActiveProcessAffinityMask;                                        //0xc0
	ULONG GdiHandleBuffer[ 34 ];                                              //0xc4
	VOID( *PostProcessInitRoutine )( );                                       //0x14c
	VOID* TlsExpansionBitmap;                                               //0x150
	ULONG TlsExpansionBitmapBits[ 32 ];                                       //0x154
	ULONG SessionId;                                                        //0x1d4
	union _ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
	union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
	VOID* pShimData;                                                        //0x1e8
	VOID* AppCompatInfo;                                                    //0x1ec
	struct UNICODE_STRING CSDVersion;                                      //0x1f0
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x1f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x1fc
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x200
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x204
	ULONG MinimumStackCommit;                                               //0x208
	VOID* SparePointers[ 4 ];                                                 //0x20c
	ULONG SpareUlongs[ 5 ];                                                   //0x21c
	VOID* WerRegistrationData;                                              //0x230
	VOID* WerShipAssertPtr;                                                 //0x234
	VOID* pUnused;                                                          //0x238
	VOID* pImageHeaderHash;                                                 //0x23c
	union
	{
		ULONG TracingFlags;                                                 //0x240
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x240
			ULONG CritSecTracingEnabled : 1;                                  //0x240
			ULONG LibLoaderTracingEnabled : 1;                                //0x240
			ULONG SpareTracingBits : 29;                                      //0x240
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
	ULONG TppWorkerpListLock;                                               //0x250
	struct _LIST_ENTRY TppWorkerpList;                                      //0x254
	VOID* WaitOnAddressHashTable[ 128 ];                                      //0x25c
	VOID* TelemetryCoverageHeader;                                          //0x45c
	ULONG CloudFileFlags;                                                   //0x460
	ULONG CloudFileDiagFlags;                                               //0x464
	CHAR PlaceholderCompatibilityMode;                                      //0x468
	CHAR PlaceholderCompatibilityModeReserved[ 7 ];                           //0x469
	struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x470
	union
	{
		ULONG LeapSecondFlags;                                              //0x474
		struct
		{
			ULONG SixtySecondEnabled : 1;                                     //0x474
			ULONG Reserved : 31;                                              //0x474
		};
	};
	ULONG NtGlobalFlag2;                                                    //0x478
}; static_assert ( sizeof( _PEB ) == 0x480 );

union __LARGE_INTEGER
{
	struct
	{
		ULONG LowPart;                                                      //0x0
		LONG HighPart;                                                      //0x4
	};
	struct
	{
		ULONG LowPart;                                                      //0x0
		LONG HighPart;                                                      //0x4
	} u;                                                                    //0x0
	LONGLONG QuadPart;                                                      //0x0
}; static_assert( sizeof( __LARGE_INTEGER ) == 0x8 );

struct LDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x8
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x10
	VOID* DllBase;                                                          //0x18
	VOID* EntryPoint;                                                       //0x1c
	ULONG SizeOfImage;                                                      //0x20
	struct UNICODE_STRING FullDllName;                                     //0x24
	struct UNICODE_STRING BaseDllName;                                     //0x2c
	union
	{
		UCHAR FlagGroup[ 4 ];                                                 //0x34
		ULONG Flags;                                                        //0x34
		struct
		{
			ULONG PackagedBinary : 1;                                         //0x34
			ULONG MarkedForRemoval : 1;                                       //0x34
			ULONG ImageDll : 1;                                               //0x34
			ULONG LoadNotificationsSent : 1;                                  //0x34
			ULONG TelemetryEntryProcessed : 1;                                //0x34
			ULONG ProcessStaticImport : 1;                                    //0x34
			ULONG InLegacyLists : 1;                                          //0x34
			ULONG InIndexes : 1;                                              //0x34
			ULONG ShimDll : 1;                                                //0x34
			ULONG InExceptionTable : 1;                                       //0x34
			ULONG ReservedFlags1 : 2;                                         //0x34
			ULONG LoadInProgress : 1;                                         //0x34
			ULONG LoadConfigProcessed : 1;                                    //0x34
			ULONG EntryProcessed : 1;                                         //0x34
			ULONG ProtectDelayLoad : 1;                                       //0x34
			ULONG ReservedFlags3 : 2;                                         //0x34
			ULONG DontCallForThreads : 1;                                     //0x34
			ULONG ProcessAttachCalled : 1;                                    //0x34
			ULONG ProcessAttachFailed : 1;                                    //0x34
			ULONG CorDeferredValidate : 1;                                    //0x34
			ULONG CorImage : 1;                                               //0x34
			ULONG DontRelocate : 1;                                           //0x34
			ULONG CorILOnly : 1;                                              //0x34
			ULONG ChpeImage : 1;                                              //0x34
			ULONG ReservedFlags5 : 2;                                         //0x34
			ULONG Redirected : 1;                                             //0x34
			ULONG ReservedFlags6 : 2;                                         //0x34
			ULONG CompatDatabaseProcessed : 1;                                //0x34
		};
	};
	USHORT ObsoleteLoadCount;                                               //0x38
	USHORT TlsIndex;                                                        //0x3a
	struct _LIST_ENTRY HashLinks;                                           //0x3c
	ULONG TimeDateStamp;                                                    //0x44
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x48
	VOID* Lock;                                                             //0x4c
	struct _LDR_DDAG_NODE* DdagNode;                                        //0x50
	struct _LIST_ENTRY NodeModuleLink;                                      //0x54
	struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0x5c
	VOID* ParentDllBase;                                                    //0x60
	VOID* SwitchBackContext;                                                //0x64
	struct RTL_BALANCED_NODE BaseAddressIndexNode;                         //0x68
	struct RTL_BALANCED_NODE MappingInfoIndexNode;                         //0x74
	ULONG OriginalBase;                                                     //0x80
	union __LARGE_INTEGER LoadTime;                                          //0x88
	ULONG BaseNameHashValue;                                                //0x90
	enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x94
	ULONG ImplicitPathOptions;                                              //0x98
	ULONG ReferenceCount;                                                   //0x9c
	ULONG DependentLoadFlags;                                               //0xa0
	UCHAR SigningLevel;                                                     //0xa4
}; static_assert ( sizeof( LDR_DATA_TABLE_ENTRY ) == 0xa8 );
#endif