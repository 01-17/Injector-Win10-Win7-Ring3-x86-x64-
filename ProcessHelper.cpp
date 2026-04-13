#include "ProcessHelper.h"

BOOL __EnableDebugPrivilege = TRUE;

BOOL CheckValidProcessExtension(const char* ValueData)
{
	if (!ValueData)
	{
		return FALSE;
	}
	unsigned int ValueDataLength = (unsigned int)strlen(ValueData);
	unsigned int v1 = (unsigned int)strlen(".exe");
	if (ValueDataLength >= v1)
		return !_stricmp(ValueData + ValueDataLength - v1, ".exe");
	return FALSE;
}

HANDLE GetProcessID(string ProcessImageName)
{
	ULONG BufferLength = 0x1000;
	void* BufferData = NULL;
	NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;



	HMODULE NtdllModuleBase = (HMODULE)GetModuleHandle01("ntdll.dll");
	LPFN_NTQUERYSYSTEMINFORMATION NtQuerySystemInformation = (LPFN_NTQUERYSYSTEMINFORMATION)GetProcAddress01(NtdllModuleBase, "NtQuerySystemInformation");



	if (NtQuerySystemInformation == NULL)
	{
		return NULL;
	}


	//获得当前进程默认堆
	//默认堆无需手动创建 / 销毁，通用、轻量的内存分配
	//附加：私有堆可用于隔离不同模块的内存（如避免 A 模块的内存碎片影响 B 模块），或针对特定场景优化（如固定大小内存块分配）。
	void* HeapHandle = GetProcessHeap();

	HANDLE ProcessID = 0;

	const char* v1 = ProcessImageName.c_str();
	std::string v2(v1);
	if (!strstr(v1, ".exe"))
	{
		v2 += ".exe";
	}


	BOOL IsLoop = FALSE;
	BOOL IsOk = FALSE;
	while (!IsLoop)
	{
		//在当前进程的默认堆中
		BufferData = HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, BufferLength);
		if (BufferData == NULL)
		{
			return NULL;
		}

		Status = NtQuerySystemInformation(SystemProcessInformation, BufferData, BufferLength, &BufferLength);
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			IsOk = TRUE;
			HeapFree(HeapHandle, NULL, BufferData);
			BufferLength *= 2;
		}
		else if (!NT_SUCCESS(Status))
		{
			HeapFree(HeapHandle, NULL, BufferData);
			return 0;
		}
		else
		{
			IsOk = FALSE;

			PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)BufferData;
			while (SystemProcessInfo)
			{
				char v1[MAX_PATH];
				memset(v1, 0, sizeof(v1));
				WideCharToMultiByte(0, 0, SystemProcessInfo->ImageName.Buffer, SystemProcessInfo->ImageName.Length, v1,
					MAX_PATH, NULL, NULL);
				if (_stricmp(v2.c_str(), v1) == 0)
				{
					ProcessID = SystemProcessInfo->UniqueProcessId;
					IsOk = TRUE;

					break;
				}

				if (!SystemProcessInfo->NextEntryOffset)
				{
					break;
				}
				SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((unsigned char*)SystemProcessInfo + SystemProcessInfo->NextEntryOffset);
			}
			if (BufferData)
			{
				HeapFree(HeapHandle, NULL, BufferData);
			}

		}

		if (ProcessID != 0)
		{
			break;
		}
		else if (!IsOk)
		{
			// Don't continuously search...
			break;
		}
	}

	return ProcessID;
}

HANDLE OpenProcess01(DWORD DesiredAccess, BOOL IsInheritHandle, HANDLE ProcessID)
{
	if (__EnableDebugPrivilege)
	{
		EnableSeDebugPrivilege(GetCurrentProcess(), TRUE);
	}
	HANDLE ProcessHandle = OpenProcess(DesiredAccess, IsInheritHandle, (DWORD)ProcessID);

	DWORD LastError = GetLastError();
	if (__EnableDebugPrivilege)
	{
		EnableSeDebugPrivilege(GetCurrentProcess(), FALSE);
	}
	SetLastError(LastError);
	return ProcessHandle;
}

BOOL EnableSeDebugPrivilege(HANDLE ProcessHandle, BOOL IsEnable)
{
	DWORD  LastError;
	HANDLE TokenHandle = 0;

	if (!OpenProcessToken(ProcessHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
	{
		LastError = GetLastError();
		if (TokenHandle)
			CloseHandle(TokenHandle);
		return LastError;
	}
	TOKEN_PRIVILEGES TokenPrivileges;
	memset(&TokenPrivileges, 0, sizeof(TOKEN_PRIVILEGES));
	LUID v1;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &v1))
	{
		LastError = GetLastError();
		CloseHandle(TokenHandle);
		return LastError;
	}
	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid = v1;
	if (IsEnable)
		TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		TokenPrivileges.Privileges[0].Attributes = 0;
	AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	LastError = GetLastError();
	CloseHandle(TokenHandle);
	return LastError;
}

int GetProcessPlatform(HANDLE ProcessHandle)
{
	//当前进程
	if (ProcessHandle == (HANDLE)((LONG_PTR)-1))
	{
#if defined(_M_IX86)
		return WIN_VERSION_X86;
#elif defined(_M_X64)
		return WIN_VERSION_X64;
#endif
	}
	switch (GetProcessorArchitecture())
	{
	case PROCESSOR_ARCHITECTURE_INTEL:
	{
		return WIN_VERSION_X86;
	}
	case PROCESSOR_ARCHITECTURE_AMD64:
	{

		ULONG_PTR IsWow64;
		NTSTATUS  Status;

		HMODULE NtDllModuleBase = (HMODULE)GetModuleHandle01("ntdll.dll");
		LPFN_NTQUERYINFORMATIONPROCESS NtQueryInformationProcess = (LPFN_NTQUERYINFORMATIONPROCESS)GetProcAddress01(NtDllModuleBase, "NtQueryInformationProcess");

		//判断目标进程
		Status = NtQueryInformationProcess(ProcessHandle, ProcessWow64Information, &IsWow64, sizeof(IsWow64), NULL);
		if (NT_SUCCESS(Status))
		{
#ifdef _WIN64
			return (IsWow64 != 0) ? WIN_VERSION_X86 : WIN_VERSION_X64;
#else
			return (IsWow64 == 0) ? WIN_VERSION_X64 : WIN_VERSION_X86;
#endif
		}
#ifdef _WIN64
		return WIN_VERSION_X64;
#else
		return WIN_VERSION_X86;
#endif
		break;

	}

	}
	return STATUS_NOT_SUPPORTED;
}

LONG GetProcessorArchitecture()
{
	static LONG volatile ProcessorArchitecture = -1;
	if (ProcessorArchitecture == -1)
	{
		SYSTEM_PROCESSOR_INFORMATION SystemeProcessorInfo;
		NTSTATUS Status;

		LPFN_RTLGETNATIVESYSTEMINFORMATION RtlGetNativeSystemInformation =
			(LPFN_RTLGETNATIVESYSTEMINFORMATION)GetProcAddress01((HMODULE)GetModuleHandle01("ntdll.dll"), "RtlGetNativeSystemInformation");

		Status = RtlGetNativeSystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessorInformation, &SystemeProcessorInfo, sizeof(SystemeProcessorInfo), NULL);
		if (Status == STATUS_NOT_IMPLEMENTED)
		{
			LPFN_NTQUERYSYSTEMINFORMATION NtQuerySystemInformation = (LPFN_NTQUERYSYSTEMINFORMATION)GetProcAddress01(GetModuleHandle01("ntdll.dll"),
				"NtQuerySystemInformation");
			Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessorInformation, &SystemeProcessorInfo, sizeof(SystemeProcessorInfo), NULL);
		}
		if (NT_SUCCESS(Status))
			_InterlockedExchange(&ProcessorArchitecture, (LONG)(SystemeProcessorInfo.ProcessorArchitecture));
	}
	return ProcessorArchitecture;
}

void* AllocateProcessMemory(HANDLE ProcessHandle, SIZE_T BufferLength)
{
	return VirtualAllocEx(ProcessHandle, NULL, BufferLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void* CommitProcessMemory(HANDLE ProcessHandle, void* BufferData, SIZE_T BufferLength)
{
	void* v1 = AllocateProcessMemory(ProcessHandle, BufferLength);
	if (v1 == NULL)
	{
		return NULL;
	}

	BOOL  IsOk = WriteProcessMemory(ProcessHandle, v1, BufferData, BufferLength, NULL);
	if (IsOk == FALSE)
	{
		return NULL;
	}

	return v1;
}

HANDLE NtCreateThreadEx(HANDLE ProcessHandle, LPVOID ThreadProcedure, LPVOID ParameterData, DWORD* ThreadID)
{
	LPFN_NTCREATETHREADEX NtCreateThreadEx = (LPFN_NTCREATETHREADEX)GetProcAddress01(GetModuleHandle01("ntdll.dll"), "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL)
	{
		return NULL;
	}
	PS_ATTRIBUTE_LIST PsAttributeList;
	ZeroMemory(&PsAttributeList, sizeof(PS_ATTRIBUTE_LIST));
	CLIENT_ID ClientID;
	ZeroMemory(&ClientID, sizeof(CLIENT_ID));

	PsAttributeList.Attributes[0].Attribute = ProcThreadAttributeValue(PS_ATTRIBUTE_CLIENTID, TRUE, FALSE, FALSE);
	PsAttributeList.Attributes[0].Size = sizeof(CLIENT_ID);
	PsAttributeList.Attributes[0].ValuePtr = (ULONG_PTR*)&ClientID;

	PsAttributeList.TotalLength = sizeof(PS_ATTRIBUTE_LIST);

	HANDLE ThreadHandle = NULL;
	HRESULT hRes = 0;

	if (!NT_SUCCESS(NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, NULL, ProcessHandle, ThreadProcedure, \
		ParameterData, 0, 0, 0x1000, 0x100000, &PsAttributeList)))
		return NULL;

	if (ThreadID)
	{
		*ThreadID = (DWORD)ClientID.UniqueThread;
	}


	return ThreadHandle;
}

BOOL ExecuteProcessMemoryData(HANDLE ProcessHandle,SHELL_CODE ShellCodeVector, BOOL IsSynchronization)
{

	void* RemoteShellCode = NULL;


	unsigned char *v1 = new unsigned char[ShellCodeVector.size()];

	for (int i = 0; i < (int)ShellCodeVector.size(); i++)
	{
		v1[i] = ShellCodeVector[i];
	}

	//在目标进程空间中申请内存并写入ShellCode
	RemoteShellCode = CommitProcessMemory(ProcessHandle, v1, ShellCodeVector.size());

	delete[] v1;

	if (RemoteShellCode == NULL)
	{
		return FALSE;
	}
	//在目标进程空间中执行远程线程
	HANDLE ThreadHandle = CreateRemoteThreadEx(ProcessHandle,(LPTHREAD_START_ROUTINE)RemoteShellCode, NULL);
	if (ThreadHandle == INVALID_HANDLE_VALUE)
	{
		FreeProcessMemory(ProcessHandle,RemoteShellCode, ShellCodeVector.size());
		
		return FALSE;
	}

	if (IsSynchronization)
	{
		WaitForSingleObject(ThreadHandle, INFINITE);
	}

	FreeProcessMemory(ProcessHandle,RemoteShellCode, ShellCodeVector.size());
	
	return TRUE;
}
HANDLE CreateRemoteThreadEx(HANDLE ProcessHandle, LPTHREAD_START_ROUTINE ThreadProcedure, LPVOID ParameterData)
{
	return NtCreateThreadEx(ProcessHandle, ThreadProcedure, ParameterData, NULL);
}
void FreeProcessMemory(HANDLE ProcessHandle,void *VirtualAddress, SIZE_T BufferLength)
{
	VirtualFreeEx(ProcessHandle, VirtualAddress, BufferLength, MEM_RELEASE);
}
std::wstring GetProcessDirectory(HANDLE ProcessHandle)
{

	PPROCESS_BASIC_INFORMATION ProcessBasicInfo = NULL;
	PEB Peb;
	PEB_LDR_DATA PebLdrData;

	//获得当前进程堆
	HANDLE	HeapHandle = GetProcessHeap();
	DWORD v1 = sizeof(PROCESS_BASIC_INFORMATION);
	ProcessBasicInfo = (PPROCESS_BASIC_INFORMATION)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, v1);

	ULONG ReturnLength = 0;

	LPFN_NTQUERYINFORMATIONPROCESS NtQueryInformationProcess = (LPFN_NTQUERYINFORMATIONPROCESS)GetProcAddress01(GetModuleHandle01("ntdll.dll"), "NtQueryInformationProcess");

	NTSTATUS Status = NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, ProcessBasicInfo, v1, &ReturnLength);
	if (Status >= 0 && v1 < ReturnLength)
	{
		if (ProcessBasicInfo)
			HeapFree(HeapHandle, 0, ProcessBasicInfo);

		ProcessBasicInfo = (PPROCESS_BASIC_INFORMATION)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, ReturnLength);
		if (!ProcessBasicInfo)
		{
			return NULL;
		}

		Status = NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, ProcessBasicInfo, ReturnLength, &ReturnLength);
	}
	if (Status >= 0)
	{
		if (ProcessBasicInfo->PebBaseAddress)
		{
			SIZE_T ReturnLength = 0;
			if (ReadProcessMemory(ProcessHandle, ProcessBasicInfo->PebBaseAddress, &Peb, sizeof(_PEB), &ReturnLength))
			{
				ReturnLength = 0;
				if (ReadProcessMemory(ProcessHandle, Peb.Ldr, &PebLdrData, sizeof(PEB_LDR_DATA), &ReturnLength))
				{
					LIST_ENTRY *ListEntry = (LIST_ENTRY *)PebLdrData.InLoadOrderModuleList.Flink;
					LIST_ENTRY *v1 = PebLdrData.InLoadOrderModuleList.Flink;

					LDR_DATA_TABLE_ENTRY v2 = { 0 };
					ReturnLength = 0;
					if (!ReadProcessMemory(ProcessHandle, (void*)v1, &v2, sizeof(LDR_DATA_TABLE_ENTRY), &ReturnLength))
					{
						if (ProcessBasicInfo)
						{
							HeapFree(HeapHandle, 0, ProcessBasicInfo);
						}
							
						return NULL;
					}

					v1 = v2.InLoadOrderModuleList.Flink;

					wchar_t v3[MAX_PATH] = { 0 };
					if (v2.BaseDllName.Length > 0)
					{
						ReturnLength = 0;
						if (ReadProcessMemory(ProcessHandle, (LPCVOID)v2.FullDllName.Buffer, &v3, v2.FullDllName.Length, &ReturnLength))
						{
							wchar_t* v4 = 0;
							v4 = wcsrchr(v3, L'\\');
							if (!v4)
								v4 = wcsrchr(v3, L'/');

							*v4++ = L'\0';

							return std::wstring(v3);
						}
					}
				}
			}
		}
	}

	if (ProcessBasicInfo)
	{
		HeapFree(HeapHandle, 0, ProcessBasicInfo);
	}

	return std::wstring();
}

