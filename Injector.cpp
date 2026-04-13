#include "Injector.h"



CInjector::CInjector()
{

}


CInjector::~CInjector()
{
}
BOOL CInjector::LoadLibraryInject(string ProcessImageName,string ModuleFullPath)
{
	//判断传入的ProcessImageName是否合法
	if (!CheckValidProcessExtension(ProcessImageName.c_str()))
	{
		return STATUS_INVALID_PARAMETER_1;
	}

	if (strlen(ModuleFullPath.c_str()) < 5)  //.dll\0
	{
		return STATUS_INVALID_PARAMETER_2;
	}

	HANDLE ProcessID = GetProcessID(ProcessImageName);
	if (ProcessID==NULL)
	{
		return FALSE;
	}
	
	HANDLE ProcessHandle = OpenProcess01(
		PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, ProcessID);

	if (ProcessHandle==NULL)
	{
		return FALSE;
	}


	int	IsOk = FALSE;


	//传递进程ID与进程句柄到CRemoter类中
	m_Remoter.OnInitMember(ProcessID, ProcessHandle);

	
	HMODULE ModuleBase = NULL;
	//测试一
	//ModuleBase = m_Remoter.LoadLibraryByPathA(ModuleFullPath.c_str());
	
	//测试二
	ModuleBase = m_Remoter.LoadLibraryByPathIntoMemoryA(ModuleFullPath.c_str(), TRUE);

	
	
	if (ModuleBase)
	{

		IsOk = TRUE;	
	}
	else
	{
		IsOk = FALSE;
	}
	CloseHandle(ProcessHandle);
	return IsOk;
}
