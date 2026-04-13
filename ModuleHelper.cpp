#include "ModuleHelper.h"


HMODULE GetModuleHandle01(const char* ModuleName)
{
	void* ModuleBase = 0;

	//获得当前线程环境块
	_TEB* Teb = (_TEB*)NtCurrentTeb();
	//通过线程块获得进程环境块
	_PEB* Peb = (_PEB*)Teb->ProcessEnvironmentBlock;
	
	PPEB_LDR_DATA PebLdrData = Peb->Ldr;
	PLDR_DATA_TABLE_ENTRY v1 = (PLDR_DATA_TABLE_ENTRY)PebLdrData->InLoadOrderModuleList.Flink;

	while (v1->DllBase)
	{
		char v2[MAX_PATH] = { 0 };
		size_t ReturnLength = 0;
		//双字转换成单字
		wcstombs_s(&ReturnLength, v2, v1->BaseDllName.Buffer, MAX_PATH);
		
		if (_stricmp(v2, ModuleName) == 0)
		{
			//获得模块在进程中的地址
			ModuleBase = v1->DllBase;
			break;
		}
		v1 = (PLDR_DATA_TABLE_ENTRY)v1->InLoadOrderModuleList.Flink;
	}
	return (HMODULE)ModuleBase;
}

void* GetProcAddress01(HMODULE ModuleBase, const char* Keyword)
{
	char* v1 = (char*)ModuleBase;

	IMAGE_DOS_HEADER* ImageDosHeader = (IMAGE_DOS_HEADER*)v1;
	IMAGE_NT_HEADERS* ImageNtHeaders = (IMAGE_NT_HEADERS*)((size_t)v1 + ImageDosHeader->e_lfanew);

	IMAGE_OPTIONAL_HEADER* ImageOptionalHeader = &ImageNtHeaders->OptionalHeader;
	IMAGE_DATA_DIRECTORY* ImageDataDirectory = (IMAGE_DATA_DIRECTORY*)(&ImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* ImageExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((size_t)v1 + ImageDataDirectory->VirtualAddress);


	if (ImageExportDirectory->NumberOfNames == 0 || ImageExportDirectory->NumberOfFunctions == 0)
	{
		return NULL;
	}

	DWORD* AddressOfFunctions = (DWORD*)((size_t)v1 + ImageExportDirectory->AddressOfFunctions);
	DWORD* AddressOfNames = (DWORD*)((size_t)v1 + ImageExportDirectory->AddressOfNames);
	WORD* AddressOfNameOrdinals = (WORD*)((size_t)v1 + ImageExportDirectory->AddressOfNameOrdinals);

	void* FunctionAddress = NULL;
	DWORD i;

	//索引导出
	if (((ULONG_PTR)Keyword >> 16) == 0)
	{
		//获取低16位
		WORD Ordinal = LOWORD(Keyword);
		ULONG_PTR Base = ImageExportDirectory->Base;

		if (Ordinal < Base || Base > Base + ImageExportDirectory->NumberOfFunctions)
		{
			return NULL;
		}
		FunctionAddress = (void*)((size_t)v1 + AddressOfFunctions[Ordinal - Base]);
	}
	else  //函数名称导出
	{
		for (i = 0; i < ImageExportDirectory->NumberOfNames; i++)
		{

			//获得函数名称
			char* FunctionName = (char*)((size_t)v1 + AddressOfNames[i]);
			if (_stricmp(Keyword, FunctionName) == 0)
			{
				FunctionAddress = (void*)((size_t)v1 + AddressOfFunctions[AddressOfNameOrdinals[i]]);
				break;
			}
		}
	}

	//函数转发器
	if ((char*)FunctionAddress >= (char*)ImageExportDirectory &&
		(char*)FunctionAddress < (char*)ImageExportDirectory + ImageDataDirectory->Size)
	{
		HMODULE v2 = 0;

		//获得转发模块的名称
		//FunctionAddress =  //Dll.Sub_1........  Dll.#2
		char* v3 = _strdup((char*)FunctionAddress);
		if (!v3)
		{
			return NULL;
		}
		char* FunctionName = strchr(v3, '.');
		*FunctionName++ = 0;

		FunctionAddress = NULL;

		//构建转发模块的路径
		char ModuleFullPath[MAX_PATH] = { 0 };
		strcpy_s(ModuleFullPath, v3);
		strcat_s(ModuleFullPath, strlen(v3) + 4 + 1, ".dll");

		//判断是不是当前进程已经加载了这个转发模块
		v2 = (HMODULE)GetModuleHandle01(ModuleFullPath);
		if (!v2)
		{
			v2 = LoadLibraryA(ModuleFullPath);
		}

		if (!v2)
		{
			return NULL;
		}


		BOOL v4 = strchr(v3, '#') == 0 ? FALSE : TRUE;
		if (v4)
		{
			//函数索引转发
			WORD FunctionOrdinal = atoi(v3 + 1);
			//递归自己
			FunctionAddress = GetProcAddress01(v2, (const char*)FunctionOrdinal);
		}
		else
		{
			//函数名称转发
			FunctionAddress = GetProcAddress01(v2, FunctionName);
		}

		free(v2);
	}
	return FunctionAddress;
}

HMODULE	GetProcessModuleHandleW(HANDLE ProcessHandle, LPCWCH ModuleName)
{
	char v1[MAX_PATH] = { 0 };
	size_t ReturnLength = 0;
	wcstombs_s(&ReturnLength, v1, ModuleName, MAX_PATH);
	return GetProcessModuleHandleA(ProcessHandle, v1);
}
HMODULE	GetProcessModuleHandleA(HANDLE ProcessHandle, LPCCH ModuleName)
{
	void*  ModuleBase = 0;


	if (ProcessHandle==NULL)
	{
		return NULL;
	}

	PPROCESS_BASIC_INFORMATION ProcessBasicInfo = NULL;
	PEB Peb;
	PEB_LDR_DATA PebLdrData;

	HMODULE NtdllModuleBase = (HMODULE)GetModuleHandle01("ntdll.dll");
	LPFN_NTQUERYINFORMATIONPROCESS NtQueryInformationProcess = 
		(LPFN_NTQUERYINFORMATIONPROCESS)GetProcAddress01(NtdllModuleBase, "NtQueryInformationProcess");


	if (NtQueryInformationProcess==NULL)
	{
		return NULL;
	}
	//获得当前进程默认堆
	HANDLE	HeapHandle = GetProcessHeap();
	DWORD v1 = sizeof(PROCESS_BASIC_INFORMATION);
	ProcessBasicInfo = (PPROCESS_BASIC_INFORMATION)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, v1);

	ULONG ReturnLength = 0;
	NTSTATUS Status = NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, ProcessBasicInfo, v1, &ReturnLength);
	if (Status >= 0 && v1 < ReturnLength)
	{
		if (ProcessBasicInfo)
		{
			HeapFree(HeapHandle, 0, ProcessBasicInfo);
		}
		ProcessBasicInfo = (PPROCESS_BASIC_INFORMATION)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, ReturnLength);
		if (!ProcessBasicInfo)
		{
			return NULL;
		}

		Status = NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, ProcessBasicInfo, ReturnLength, &ReturnLength);
	}

	//枚举成功
	if (Status >= 0)
	{
		//获取目标进程Peb地址
		if (ProcessBasicInfo->PebBaseAddress)
		{
			SIZE_T ReturnLength = 0;
			if (ReadProcessMemory(ProcessHandle, ProcessBasicInfo->PebBaseAddress, &Peb, sizeof(PEB), &ReturnLength))
			{
				ReturnLength = 0;
				if (ReadProcessMemory(ProcessHandle, Peb.Ldr, &PebLdrData, sizeof(PEB_LDR_DATA), &ReturnLength))
				{
					LIST_ENTRY *ListEntry = (LIST_ENTRY *)PebLdrData.InLoadOrderModuleList.Flink;
					LIST_ENTRY *v1 = PebLdrData.InLoadOrderModuleList.Flink;
					do
					{
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
						char v4[MAX_PATH] = { 0 };
						if (v2.BaseDllName.Length > 0)
						{
							ReturnLength = 0;
							if (ReadProcessMemory(ProcessHandle, (LPCVOID)v2.BaseDllName.Buffer, &v3, v2.BaseDllName.Length, &ReturnLength))
							{
								size_t ReturnLength = 0;
								wcstombs_s(&ReturnLength, v4, v3, MAX_PATH);
							}
						}

						if (v2.DllBase != nullptr && v2.SizeOfImage != 0)
						{
							if (_stricmp(v4, ModuleName) == 0)
							{
								ModuleBase = v2.DllBase;
								break;
							}
						}

					} while (ListEntry != v1);

				} 
			} 
		}
	}

	if (ProcessBasicInfo)
	{
		HeapFree(HeapHandle, 0, ProcessBasicInfo);
	}

	return (HMODULE)ModuleBase;
}


