#include "_tmain.h"



void _tmain()
{


	CHAR v1[MAX_PATH] = { 0 };
	//获得当前目录
	GetCurrentDirectoryA(MAX_PATH, v1);
	//通过目标进程的完整路径进行数据的读取

	//追加字符串
	strcat(v1,("\\Dll.dll"));
	CInjector Injector;

	Injector.LoadLibraryInject("Taskmgr.exe", v1);



}