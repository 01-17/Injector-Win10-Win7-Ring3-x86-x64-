#include "SystemHelper.h"


BOOL SeIsWindowsVersionOrLater(OS_TYPE TargetVersion)
{
	if (TargetVersion == OS_TYPE_WINDOWS_10)
	{
		typedef LONG(__stdcall* LPFN_RTLGETVERSION)(PRTL_OSVERSIONINFOW lpVersionInformation);
		static LPFN_RTLGETVERSION _RtlGetVersion = (LPFN_RTLGETVERSION)GetProcAddress01((HMODULE)GetModuleHandle01("ntdll.dll"), "RtlGetVersion");

		RTL_OSVERSIONINFOEXW VersionInfo = { 0 };
		VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);

		if (_RtlGetVersion != 0 && _RtlGetVersion((PRTL_OSVERSIONINFOW)&VersionInfo) == 0)
		{
			return (VersionInfo.dwMajorVersion == 10);
		}
		return FALSE;
	}

	OSVERSIONINFOEX VersionInfo;
	memset(&VersionInfo, 0, sizeof(OSVERSIONINFOEX));
	VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

	if (TargetVersion >= OS_TYPE_WINDOWS_VISTA)
	{
		VersionInfo.dwMajorVersion = 6;

		switch (TargetVersion)
		{
		case OS_TYPE_WINDOWS_VISTA:   VersionInfo.dwMinorVersion = 0; break;
		case OS_TYPE_WINDOWS_7:   VersionInfo.dwMinorVersion = 1; break;
		case OS_TYPE_WINDOWS_8:	  VersionInfo.dwMinorVersion = 2; break;
		default: break;
		}
	}
	else
	{
		VersionInfo.dwMajorVersion = 5;
		VersionInfo.dwMinorVersion = TargetVersion >= OS_TYPE_WINDOWS_XP ? 1 : 0;
	}

	DWORDLONG v1 = 0;

	VER_SET_CONDITION(v1, VER_MAJORVERSION, VER_GREATER_EQUAL);
	VER_SET_CONDITION(v1, VER_MINORVERSION, VER_GREATER_EQUAL);
	VER_SET_CONDITION(v1, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
	VER_SET_CONDITION(v1, VER_SERVICEPACKMINOR, VER_GREATER_EQUAL);

	return VerifyVersionInfo(&VersionInfo, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR, v1) != FALSE;
}
