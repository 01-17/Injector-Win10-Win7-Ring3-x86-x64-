#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
#include <map>
#include "Common.h"
#include "ProcessHelper.h"
#include "ModuleHelper.h"
#include "FileHelper.h"
#include "PeHelper.h"
#include "SystemHelper.h"
#include "APISet.h"
using namespace std;




//节表
#define MakePtr(Cast, DataValue1, DataValue2) (Cast)((DWORD_PTR)(DataValue1) + (DWORD_PTR)(DataValue2))



//重定向表
#ifndef IMR_RELTYPE
#define IMR_RELTYPE(DataValue)				((DataValue >> 12) & 0xF)
#endif

#ifndef IMR_RELOFFSET
#define IMR_RELOFFSET(DataValue)			(DataValue & 0xFFF)
#endif




typedef enum {
	CALLING_CONVENTION_CDECL = 0,
	CALLING_CONVENTION_STDCALL,
	CALLING_CONVENTION_THISCALL,
	CALLING_CONVENTION_FASTCALL,
	CALLING_CONVENTION_WIN64
}CALLING_CONVENTION;



typedef enum {
	PARAMETER_TYPE_INT = 0,
	PARAMETER_TYPE_INT64,
	PARAMETER_TYPE_BOOL,
	PARAMETER_TYPE_SHORT,
	PARAMETER_TYPE_FLOAT,
	PARAMETER_TYPE_DOUBLE,
	PARAMETER_TYPE_BYTE,
	PARAMETER_TYPE_POINTER,
	PARAMETER_TYPE_STRING,
	PARAMETER_TYPE_WSTRING,
	PARAMETER_TYPE_UNICODE_STRING
}PARAMETER_TYPE;

#ifdef _WIN64
#define _PARAMETER_TYPE_DWORD(ParameterType)  ParameterType  == PARAMETER_TYPE_INT    || ParameterType == PARAMETER_TYPE_FLOAT   || ParameterType == PARAMETER_TYPE_SHORT
#define _PARAMETER_TYPE_QWORD(ParameterType)  ParameterType  == PARAMETER_TYPE_INT64  || ParameterType == PARAMETER_TYPE_DOUBLE  || ParameterType == PARAMETER_TYPE_POINTER || ParameterType == PARAMETER_TYPE_STRING || ParameterType == PARAMETER_TYPE_WSTRING
#define _PARAMETER_TYPE_STRING(ParameterType) ParameterType  == PARAMETER_TYPE_STRING || ParameterType == PARAMETER_TYPE_WSTRING || ParameterType == PARAMETER_TYPE_UNICODE_STRING
#else
#define _PARAMETER_TYPE_DWORD(ParameterType)  ParameterType  == PARAMETER_TYPE_INT    || ParameterType == PARAMETER_TYPE_FLOAT   || ParameterType == PARAMETER_TYPE_SHORT   || ParameterType == PARAMETER_TYPE_POINTER || ParameterType == PARAMETER_TYPE_STRING || ParameterType == PARAMETER_TYPE_WSTRING
#define _PARAMETER_TYPE_QWORD(ParameterType)  ParameterType  == PARAMETER_TYPE_INT64  || ParameterType == PARAMETER_TYPE_DOUBLE
#define _PARAMETER_TYPE_STRING(ParameterType) ParameterType  == PARAMETER_TYPE_STRING || ParameterType == PARAMETER_TYPE_WSTRING || ParameterType == PARAMETER_TYPE_UNICODE_STRING
#endif

typedef enum {
	PARAMETER_INDEX_RCX,
	PARAMETER_INDEX_RDX,
	PARAMETER_INDEX_R8,
	PARAMETER_INDEX_R9,
	PARAMETER_INDEX_MAX
}PARAMETER_INDEX;


typedef struct {
	PARAMETER_TYPE			ParameterType;
	void*					ParameterData;
} PARAMETER_INFORMATION;


typedef struct {
	ULONG	BufferLength;
	void*	BufferData;
}STRING_INFORMATION;

typedef struct {
	ULONG	BufferLength;
	void*	BufferData;
}STRUCT_INFORMATION;



typedef struct {
	CALLING_CONVENTION		CallingConvention;			   //函数的调用约定
	vector<PARAMETER_INFORMATION>	ParameterInfoVector;   //函数的参数信息
	vector<STRING_INFORMATION>		StringInfoVector;      //目标进程空间中申请的String结构
	vector<STRUCT_INFORMATION>		StructInfoVector;      //目标进程空间中申请的UnicodeString结构
#ifdef _WIN64
	unsigned __int64			CallingAddress;      //呼叫的函数地址
#else
	unsigned long				CallingAddress;
#endif

}INVOKE_INFORMATION;


typedef std::map<std::wstring, std::vector<std::wstring>> mapAPI_SCHEMA;

class CRemoter
{
public:
	CRemoter();
	~CRemoter();
	void CRemoter::OnInitMember(HANDLE ProcessID, HANDLE ProcessHandle);
	void CRemoter::OnFreeMember();
	HMODULE CRemoter::LoadLibraryByPathA(LPCCH ModuleFullPath, ULONG Flags = NULL);
	HMODULE CRemoter::LoadLibraryByPathW(LPCWCH ModuleFullPath, ULONG Flags = NULL);


	HMODULE	CRemoter::LoadLibraryByPathIntoMemoryA(LPCCH ModuleFullPath, BOOL IsPEHeader);
	HMODULE	CRemoter::LoadLibraryByPathIntoMemoryW(LPCWCH ModuleFullPath, BOOL IsPEHeader);
	HMODULE CRemoter::LoadLibraryFromMemory(PVOID FileData, DWORD FileLength, BOOL IsPEHeader);

	FARPROC CRemoter::GetProcessProcAddressW(HMODULE ModuleBase, LPCWCH Keyword);
	FARPROC CRemoter::GetProcessProcAddressA(HMODULE ModuleBase, LPCCH Keyword);
	DWORD CRemoter::CreateProcessProcedureCallEnvironment(BOOL IsThread = FALSE);
	//目标进程中创建一个线程
	DWORD CRemoter::CreateProcessWorkerThread();
	//在目标进程中的线程中创建一个事件
	BOOL CRemoter::CreateProcessAPCEvent(DWORD ThreadID);
	void CRemoter::ExitThreadWithStatus();
	void CRemoter::SaveReturnValueAndSignalEvent();
	DWORD CRemoter::ExecuteInWorkerThread(SHELL_CODE ShellCodeVector, size_t&ReturnValue);
	DWORD CRemoter::TerminateWorkerThread();

	//修正模块导入表
	BOOL CRemoter::FixProcessImportTable(PVOID BaseAddress /*本地文件粒度对齐*/, PVOID RemoteBaseAddress /*远程内存粒度对齐*/);
	//修正模块延迟导入表
	BOOL CRemoter::FixProcessDelayedImportTable(PVOID BaseAddress /*本地文件粒度对齐*/, PVOID RemoteBaseAddress /*远程内存粒度对齐*/);
	//修正模块重定向表
	BOOL CRemoter::FixProcessBaseRelocationTable(PVOID BaseAddress /*本地文件粒度对齐*/, PVOID RemoteBaseAddress /*远程内存粒度对齐*/);
	BOOL CRemoter::FixProcessBaseRelocationItem(size_t Delta /*差值*/, WORD ImageRelocationItem, PBYTE VirtualAddress);
	//修正节头部信息
	BOOL CRemoter::FixProcessSections(PVOID BaseAddress/*本地文件粒度对齐*/, PVOID RemoteBaseAddress/*远程内存粒度对齐*/, BOOL IsPEHeader);
	BOOL CRemoter::FixProcessSection(BYTE* SectionName/*节名称*/, PVOID BaseAddress/*本地文件粒度对齐*/, PVOID RemoteBaseAddress/*远程内存粒度对齐*/, \
		ULONGLONG PointerToRawData/*文件粒度对齐的节偏移*/, ULONGLONG VirtualAddress/*内存粒度对齐的节偏移*/, ULONGLONG SizeOfRawData/*文件粒度对齐的节大小*/, ULONGLONG VirtualSize/*节真实大小*/, ULONG Protection/*节属性*/);
	//TLSCallBack
	BOOL CRemoter::ExecuteProcessTLSCallBack(PVOID BaseAddress, PVOID RemoteBaseAddress);
	BOOL CRemoter::CallEntryPoint(void* BaseAddress, FARPROC EntryPoint);
	BOOL CRemoter::InitializeCookie(PVOID BaseAddress, PVOID RemoteBaseAddress);

	void CRemoter::AddByteToBuffer(unsigned char DataValue);
	void CRemoter::AddLongToBuffer(unsigned long DataValue);
	void CRemoter::AddLong64ToBuffer(unsigned __int64 DataValue);
	
	void CRemoter::PushCall(CALLING_CONVENTION CallingConvention, FARPROC CallingAddress);
	void CRemoter::PushAllParameters(BOOL IsRightToLeft);
	void CRemoter::PushParameter(PARAMETER_TYPE ParameterType, void *ParameterData);
	void CRemoter::PushInt(int DataValue);
	void CRemoter::PushInt64(__int64 DataValue);
	void CRemoter::PushUInt64(unsigned __int64 DataValue);
	void CRemoter::PushUnicodeStringStructure(UNICODE_STRING* DataValue);
	void CRemoter::PushUnicodeString(const wchar_t* DataValue);
	void CRemoter::PushPointer(void* DataValue);

	void CRemoter::BeginCall64();
	void CRemoter::EndCall64();
	void CRemoter::LoadStringParameter64(PARAMETER_INFORMATION ParameterInfo, PARAMETER_INDEX ParameterIndex);
	BOOL CRemoter::LoadParameter64(unsigned __int64 ParameterData, PARAMETER_INDEX ParameterIndex);

	DWORD CRemoter::ResolvePath(std::wstring& FileFullPath, RESOLVE_FLAG ResolveFlag, const std::wstring& BaseName=L"");
	DWORD CRemoter::ProbeSxSRedirect(std::wstring& FileFullPath);
private:
	//目标进程ID与进程句柄
	HANDLE m_ProcessID = 0;	
	HANDLE m_ProcessHandle = NULL;
	BOOL   m_Is64Bit;
	INVOKE_INFORMATION	  m_CurrentInvokeInfo;
	SHELL_CODE            m_LocalShellCodeVector;                         //在当前进程中组合ShellCode
	
	
	 //LoadLibraryFromMemory使用以下成员
	HANDLE m_WorkerThreadID = 0;                                          //关联命名事件
	HANDLE m_WorkerThreadHandle = NULL;                                   
	HANDLE m_WaitEventHandle = NULL;                                      //APC异步事件
	void*				  m_RemoteWorkerCode = NULL;                      //目标进程中申请的0x1000内存         
	void*				  m_RemoteWorkerCodeThread = NULL;                //m_RemoteWorkerCode + 4 * sizeof(size_t)
	size_t				  m_RemoteWorkerCodeThreadLength = 0;

	


	mapAPI_SCHEMA m_ApiSchemaMap;
	BOOL InitializeApiSchema()
	{
		if (SeIsWindowsVersionOrLater(OS_TYPE_WINDOWS_10))
		{
			return Initialize_T<PAPI_SET_NAMESPACE_ARRAY_10, PAPI_SET_NAMESPACE_ENTRY_10, PAPI_SET_VALUE_ARRAY_10, PAPI_SET_VALUE_ENTRY_10>();
		}
		else if (SeIsWindowsVersionOrLater(OS_TYPE_WINDOWS_8))
			return Initialize_T<PAPI_SET_NAMESPACE_ARRAY, PAPI_SET_NAMESPACE_ENTRY, PAPI_SET_VALUE_ARRAY, PAPI_SET_VALUE_ENTRY>();              //没有测试
		else if (SeIsWindowsVersionOrLater(OS_TYPE_WINDOWS_7))
			return Initialize_T<PAPI_SET_NAMESPACE_ARRAY_V2, PAPI_SET_NAMESPACE_ENTRY_V2, PAPI_SET_VALUE_ARRAY_V2, PAPI_SET_VALUE_ENTRY_V2>();  //没有测试
		else
			return TRUE;		
	}
	template<typename T1, typename T2, typename T3, typename T4>
	BOOL Initialize_T()
	{
		if (!m_ApiSchemaMap.empty())
		{
			//数据不为空
			return TRUE;
		}
		//从当前进程的Teb获取Peb值
		PEB_T *Peb = reinterpret_cast<PEB_T*>(reinterpret_cast<TEB_T*>(NtCurrentTeb())->ProcessEnvironmentBlock);
		T1 ApiSetMap = reinterpret_cast<T1>(Peb->ApiSetMap);

		for (DWORD i = 0; i < ApiSetMap->Count; i++)
		{
			T2 Descriptor = ApiSetMap->Entry(i);

			std::vector<std::wstring> v6;
			wchar_t DllName[MAX_PATH] = { 0 };

			ApiSetMap->GetApiName(Descriptor, DllName);
			std::transform(DllName, DllName + MAX_PATH, DllName, ::tolower);

			T3 HostData = ApiSetMap->GetValueArray(Descriptor);

			for (DWORD j = 0; j < HostData->Count; j++)
			{
				T4 v4 = HostData->Entry(ApiSetMap, j);
				std::wstring v5((wchar_t*)((BYTE*)ApiSetMap + v4->ValueOffset), v4->ValueLength / sizeof(wchar_t));

				if (!v5.empty())
					v6.push_back(v5);
			}
			m_ApiSchemaMap.insert(std::make_pair(DllName, v6));
		}

		return TRUE;
	}
};

