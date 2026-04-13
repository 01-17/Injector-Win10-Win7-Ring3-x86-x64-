#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
#include "ModuleHelper.h"
#include "Common.h"
using namespace std;


enum OS_TYPE
{
	OS_TYPE_UNKNOWN = 0,

	OS_TYPE_WINDOWS_2000 = 0x4105,
	OS_TYPE_WINDOWS_XP = 0x4106,
	OS_TYPE_WINDOWS_VISTA = 0x4107,
	OS_TYPE_WINDOWS_7 = 0x4108,
	OS_TYPE_WINDOWS_8 = 0x4109,
	OS_TYPE_WINDOWS_10 = 0x4110,

	OS_TYPE_WINDOWS = 0x4000,   /**< To test whether any version of Windows is running,
						you can use the expression ((getOperatingSystemType() & Windows) != 0). */
};


BOOL SeIsWindowsVersionOrLater(OS_TYPE TargetVersion);