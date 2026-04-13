#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
#include "ModuleHelper.h"
#include "Common.h"
using namespace std;


enum {
	WIN_VERSION_UNKNOWN,
	WIN_VERSION_X86,
	WIN_VERSION_X64
};

typedef enum _PS_ATTRIBUTE_NUMBER {
	PS_ATTRIBUTE_PARENT_PROCESS,			// IN HANDLE
	PS_ATTRIBUTE_DEBUG_PORT,				// IN HANDLE
	PS_ATTRIBUTE_TOKEN,						// IN HANDLE
	PS_ATTRIBUTE_CLIENTID,					// OUT PCLIENT_ID
	PS_ATTRIBUTE_TEB_ADDRESS,				// OUT PTEB
	PS_ATTRIBUTE_IMAGE_NAME,				// IN PWSTR
	PS_ATTRIBUTE_IMAGE_INFO,				// OUT PSECTION_IMAGE_INFORMATION
	PS_ATTRIBUTE_MEMORY_RESERVE,			// IN PPS_MEMORY_RESERVE
	PS_ATTRIBUTE_PRIORITY_CLASS,			// IN UCHAR
	PS_ATTRIBUTE_ERROR_MODE,				// IN ULONG
	PS_ATTRIBUTE_STD_HANDLE_INFO,			// 10, IN PPS_STD_HANDLE_INFO
	PS_ATTRIBUTE_HANDLE_LIST,				// IN PHANDLE
	PS_ATTRIBUTE_GROUP_AFFINITY,			// IN PGROUP_AFFINITY
	PS_ATTRIBUTE_PREFERRED_NODE,			// IN PUSHORT
	PS_ATTRIBUTE_IDEALP_ROCESSOR,			// IN PPROCESSOR_NUMBER
	PS_ATTRIBUTE_UMS_THREAD,				// SEE UPDATEPROCETHREADATTRIBUTELIST IN MSDN (CREATEPROCESSA/W...) IN PUMS_CREATE_THREAD_ATTRIBUTES
	PS_ATTRIBUTE_MITIGATION_OPTIONS,		// IN UCHAR
	PS_ATTRIBUTE_PROTECTION_LEVEL,
	PS_ATTRIBUTE_SECURE_PROCESS,			// SINCE THRESHOLD (VIRTUAL SECURE MODE, DEVICE GUARD)
	PS_ATTRIBUTE_JOB_LIST,
	PS_ATTRIBUTE_MAX
} PS_ATTRIBUTE_NUMBER;

typedef struct _PS_ATTRIBUTE
{
	ULONG Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;


typedef struct _OBJECT_ATTRIBUTES64
{
	ULONG Length;
	ULONG64 RootDirectory;
	ULONG64 ObjectName;
	ULONG Attributes;
	ULONG64 SecurityDescriptor;
	ULONG64 SecurityQualityOfService;
} OBJECT_ATTRIBUTES64, *POBJECT_ATTRIBUTES64;


typedef NTSTATUS(NTAPI *LPFN_NTCREATETHREADEX)
(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES64 ObjectAttributes,
	__in HANDLE ProcessHandle,
	__in PVOID StartRoutine,
	__in_opt PVOID Argument,
	__in ULONG CreateFlags,
	__in_opt ULONG_PTR ZeroBits,
	__in_opt SIZE_T StackSize,
	__in_opt SIZE_T MaximumStackSize,
	__in_opt PPS_ATTRIBUTE_LIST AttributeList);


typedef vector<unsigned char>	SHELL_CODE;

BOOL CheckValidProcessExtension(const char* ValueData);     //判断进程名称合法
HANDLE GetProcessID(string ProcessImageName);
HANDLE OpenProcess01(DWORD DesiredAccess, BOOL IsInheritHandle, HANDLE ProcessID);
BOOL EnableSeDebugPrivilege(HANDLE ProcessHandle, BOOL IsEnable);
int  GetProcessPlatform(HANDLE ProcessHandle);
LONG GetProcessorArchitecture();

//在目标进程中进行内存申请
void* AllocateProcessMemory(HANDLE ProcessHandle, SIZE_T BufferLength);

//在目标进程中进行内存申请与写操作
void* CommitProcessMemory(HANDLE ProcessHandle, void* BufferData, SIZE_T BufferLength);
HANDLE NtCreateThreadEx(HANDLE ProcessHandle, LPVOID ThreadProcedure, LPVOID ParameterData, DWORD* ThreadID);

//执行目标进程中的ShellCode
BOOL ExecuteProcessMemoryData(HANDLE ProcessHandle,SHELL_CODE ShellCodeVector, BOOL IsSynchronization = TRUE);
HANDLE CreateRemoteThreadEx(HANDLE ProcessHandle,LPTHREAD_START_ROUTINE ThreadProcedure, LPVOID ParameterData);
void FreeProcessMemory(HANDLE ProcessHandle,void *VirtualAddress, SIZE_T BufferLength);
std::wstring GetProcessDirectory(HANDLE ProcessHandle);