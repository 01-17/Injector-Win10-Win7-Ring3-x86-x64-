#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
#include "ModuleHelper.h"
#include "Common.h"
using namespace std;
template <class T>
struct _LIST_ENTRY_T
{
	T Flink;
	T Blink;
};

template <class T>
struct _UNICODE_STRING_T
{
	union
	{
		struct
		{
			WORD Length;
			WORD MaximumLength;
		};
		T dummy;
	};
	T Buffer;
};

template <typename T, typename NGF, int A>
struct _PEB_T
{
	typedef T type;

	union
	{
		struct
		{
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE BitField;
		};
		T dummy01;
	};
	T Mutant;
	T ImageBaseAddress;
	T Ldr;
	T ProcessParameters;
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T AtlThunkSListPtr;
	T IFEOKey;
	T CrossProcessFlags;
	T UserSharedInfoPtr;
	DWORD SystemReserved;
	DWORD AtlThunkSListPtr32;
	T ApiSetMap;
	T TlsExpansionCounter;
	T TlsBitmap;
	DWORD TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T HotpatchInformation;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union
	{
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	T ProcessHeaps;
	T GdiSharedHandleTable;
	T ProcessStarterHelper;
	T GdiDCAttributeList;
	T LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	T ImageSubsystemMinorVersion;
	T ActiveProcessAffinityMask;
	T GdiHandleBuffer[A];
	T PostProcessInitRoutine;
	T TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	T SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	T pShimData;
	T AppCompatInfo;
	_UNICODE_STRING_T<T> CSDVersion;
	T ActivationContextData;
	T ProcessAssemblyStorageMap;
	T SystemDefaultActivationContextData;
	T SystemAssemblyStorageMap;
	T MinimumStackCommit;
	T FlsCallback;
	_LIST_ENTRY_T<T> FlsListHead;
	T FlsBitmap;
	DWORD FlsBitmapBits[4];
	T FlsHighIndex;
	T WerRegistrationData;
	T WerShipAssertPtr;
	T pContextData;
	T pImageHeaderHash;
	T TracingFlags;
	T CsrServerReadOnlySharedMemoryBase;
};


typedef _PEB_T<DWORD, DWORD64, 34> _PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> _PEB64;

#ifdef _WIN64
typedef _PEB64 PEB_T;
#else
typedef _PEB32 PEB_T;
#endif


template <class T>
struct _NT_TIB_T
{
	T ExceptionList;
	T StackBase;
	T StackLimit;
	T SubSystemTib;
	T FiberData;
	T ArbitraryUserPointer;
	T Self;
};

template <typename T>
struct _CLIENT_ID_T
{
	T UniqueProcess;
	T UniqueThread;
};

template <typename T>
struct _GDI_TEB_BATCH_T
{
	DWORD Offset;
	T HDC;
	DWORD Buffer[310];
};
template <typename T>
struct _TEB_T
{
	typedef T type;

	_NT_TIB_T<T> NtTib;
	T EnvironmentPointer;
	_CLIENT_ID_T<T> ClientId;
	T ActiveRpcHandle;
	T ThreadLocalStoragePointer;
	T ProcessEnvironmentBlock;
	DWORD LastErrorValue;
	DWORD CountOfOwnedCriticalSections;
	T CsrClientThread;
	T Win32ThreadInfo;
	DWORD User32Reserved[26];
	T UserReserved[5];
	T WOW32Reserved;
	DWORD CurrentLocale;
	DWORD FpSoftwareStatusRegister;
	T SystemReserved1[54];
	DWORD ExceptionCode;
	T ActivationContextStackPointer;
	BYTE SpareBytes[36];
	DWORD TxFsContext;
	_GDI_TEB_BATCH_T<T> GdiTebBatch;
	_CLIENT_ID_T<T> RealClientId;
	T GdiCachedProcessHandle;
	DWORD GdiClientPID;
	DWORD GdiClientTID;
	T GdiThreadLocalInfo;
	T Win32ClientInfo[62];
	T glDispatchTable[233];
	T glReserved1[29];
	T glReserved2;
	T glSectionInfo;
	T glSection;
	T glTable;
	T glCurrentRC;
	T glContext;
	DWORD LastStatusValue;
	_UNICODE_STRING_T<T> StaticUnicodeString;
	wchar_t StaticUnicodeBuffer[261];
	T DeallocationStack;
	T TlsSlots[64];
	_LIST_ENTRY_T<T> TlsLinks;
	T Vdm;
	T ReservedForNtRpc;
	T DbgSsReserved[2];
	DWORD HardErrorMode;
	T Instrumentation[11];
	_GUID ActivityId;
	T SubProcessTag;
	T PerflibData;
	T EtwTraceData;
	T WinSockData;
	DWORD GdiBatchCount;
	DWORD IdealProcessorValue;
	DWORD GuaranteedStackBytes;
	T ReservedForPerf;
	T ReservedForOle;
	DWORD WaitingOnLoaderLock;
	T SavedPriorityState;
	T ReservedForCodeCoverage;
	T ThreadPoolData;
	T TlsExpansionSlots;
	T DeallocationBStore;
	T BStoreLimit;
	DWORD MuiGeneration;
	DWORD IsImpersonating;
	T NlsCache;
	T pShimData;
	USHORT HeapVirtualAffinity;
	USHORT LowFragHeapDataSlot;
	T CurrentTransactionHandle;
	T ActiveFrame;
	T FlsData;
	T PreferredLanguages;
	T UserPrefLanguages;
	T MergedPrefLanguages;
	DWORD MuiImpersonation;
	USHORT CrossTebFlags;
	USHORT SameTebFlags;
	T TxnScopeEnterCallback;
	T TxnScopeExitCallback;
	T TxnScopeContext;
	DWORD LockCount;
	DWORD SpareUlong0;
	T ResourceRetValue;
	T ReservedForWdf;
};

typedef _TEB_T<DWORD>     _TEB32;
typedef _TEB_T<DWORD64>   _TEB64;
typedef _TEB_T<DWORD_PTR>  TEB_T;





typedef struct _API_SET_VALUE_ENTRY_10
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY_10, *PAPI_SET_VALUE_ENTRY_10;

typedef struct _API_SET_VALUE_ARRAY_10
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG Unk;
	ULONG NameLength;
	ULONG DataOffset;
	ULONG Count;

	inline PAPI_SET_VALUE_ENTRY_10 Entry(void* ParameterData, DWORD i)
	{
		return (PAPI_SET_VALUE_ENTRY_10)((BYTE*)ParameterData + DataOffset + i * sizeof(API_SET_VALUE_ENTRY_10));
	}
} API_SET_VALUE_ARRAY_10, *PAPI_SET_VALUE_ARRAY_10;

typedef struct _API_SET_NAMESPACE_ENTRY_10
{
	ULONG Limit;
	ULONG Size;
} API_SET_NAMESPACE_ENTRY_10, *PAPI_SET_NAMESPACE_ENTRY_10;

typedef struct _API_SET_NAMESPACE_ARRAY_10
{
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG Start;
	ULONG End;
	ULONG Unknown[2];

	inline PAPI_SET_NAMESPACE_ENTRY_10 Entry(DWORD i)
	{
		return (PAPI_SET_NAMESPACE_ENTRY_10)((BYTE*)this + End + i * sizeof(API_SET_NAMESPACE_ENTRY_10));
	}

	inline PAPI_SET_VALUE_ARRAY_10 GetValueArray(PAPI_SET_NAMESPACE_ENTRY_10 ParameterData)
	{
		return (PAPI_SET_VALUE_ARRAY_10)((BYTE*)this + Start + sizeof(API_SET_VALUE_ARRAY_10) * ParameterData->Size);
	}

	inline void GetApiName(PAPI_SET_NAMESPACE_ENTRY_10 ParameterData, wchar_t* BufferData)
	{
		auto v1 = GetValueArray(ParameterData);

		//注意这个代码数据可能不对
		memcpy(BufferData, (char*)this + v1->NameOffset, v1->Unk);
		wcscat(BufferData, L".dll");
	
	}
} API_SET_NAMESPACE_ARRAY_10, *PAPI_SET_NAMESPACE_ARRAY_10;


typedef struct _API_SET_VALUE_ENTRY
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY, *PAPI_SET_VALUE_ENTRY;

typedef struct _API_SET_VALUE_ARRAY
{
	ULONG Flags;
	ULONG Count;
	API_SET_VALUE_ENTRY Array[ANYSIZE_ARRAY];

	inline PAPI_SET_VALUE_ENTRY Entry(void* /*pApiSet*/, DWORD i)
	{
		return Array + i;
	}
} API_SET_VALUE_ARRAY, *PAPI_SET_VALUE_ARRAY;

typedef struct _API_SET_NAMESPACE_ENTRY
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG AliasOffset;
	ULONG AliasLength;
	ULONG DataOffset;
} API_SET_NAMESPACE_ENTRY, *PAPI_SET_NAMESPACE_ENTRY;

typedef struct _API_SET_NAMESPACE_ARRAY
{
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	API_SET_NAMESPACE_ENTRY Array[ANYSIZE_ARRAY];

	inline PAPI_SET_NAMESPACE_ENTRY Entry(DWORD i)
	{
		return Array + i;
	}

	inline PAPI_SET_VALUE_ARRAY GetValueArray(PAPI_SET_NAMESPACE_ENTRY ParameterData)
	{
		return (PAPI_SET_VALUE_ARRAY)((BYTE*)this + ParameterData->DataOffset);
	}

	inline void GetApiName(PAPI_SET_NAMESPACE_ENTRY ParameterData, wchar_t* BufferData)
	{
		memcpy(BufferData, (char*)this + ParameterData->NameOffset, ParameterData->NameLength);
		
	}
} API_SET_NAMESPACE_ARRAY, *PAPI_SET_NAMESPACE_ARRAY;


//
// Win 8 and 7
//
typedef struct _API_SET_VALUE_ENTRY_V2
{
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY_V2, *PAPI_SET_VALUE_ENTRY_V2;

typedef struct _API_SET_VALUE_ARRAY_V2
{
	ULONG Count;
	API_SET_VALUE_ENTRY_V2 Array[ANYSIZE_ARRAY];

	inline PAPI_SET_VALUE_ENTRY_V2 Entry(void* /*pApiSet*/, DWORD i)
	{
		return Array + i;
	}
} API_SET_VALUE_ARRAY_V2, *PAPI_SET_VALUE_ARRAY_V2;

typedef struct _API_SET_NAMESPACE_ENTRY_V2
{
	ULONG NameOffset;
	ULONG NameLength;
	ULONG DataOffset;   // API_SET_VALUE_ARRAY
} API_SET_NAMESPACE_ENTRY_V2, *PAPI_SET_NAMESPACE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_ARRAY_V2
{
	ULONG Version;
	ULONG Count;
	API_SET_NAMESPACE_ENTRY_V2 Array[ANYSIZE_ARRAY];

	inline PAPI_SET_NAMESPACE_ENTRY_V2 Entry(DWORD i)
	{
		return Array + i;
	}

	inline PAPI_SET_VALUE_ARRAY_V2 GetValueArray(PAPI_SET_NAMESPACE_ENTRY_V2 ParameterData)
	{
		return (PAPI_SET_VALUE_ARRAY_V2)((BYTE*)this + ParameterData->DataOffset);
	}

	inline void GetApiName(PAPI_SET_NAMESPACE_ENTRY_V2 ParameterData, wchar_t* BufferData)
	{
	   memcpy(BufferData, (char*)this + ParameterData->NameOffset, ParameterData->NameLength);
	
	}
} API_SET_NAMESPACE_ARRAY_V2, *PAPI_SET_NAMESPACE_ARRAY_V2;
