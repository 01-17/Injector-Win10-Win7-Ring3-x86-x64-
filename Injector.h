#pragma once
#include <windows.h>
#include <iostream>
#include "Common.h"
#include "Remoter.h"
#include "ProcessHelper.h"
#include "ModuleHelper.h"
using namespace std;






class CInjector
{
public:

	CInjector::CInjector();
	~CInjector();
	
	BOOL CInjector::LoadLibraryInject(string ProcessImageName, string ModuleFullPath);
private:
	CRemoter m_Remoter;
};

