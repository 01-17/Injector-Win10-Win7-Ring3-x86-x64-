#pragma once
#include <windows.h>
#include <iostream>
#include <algorithm>
#include "Common.h"
#include "ModuleHelper.h"
#include "ProcessHelper.h"


using namespace std;

typedef
struct _FILE_INFORMATION_
{
	PVOID	FileData;
	int     FileLength;

	BOOL IsValid() { return (FileData && FileLength); }
}FILE_INFORMATION,*PFILE_INFORMATION;


FILE_INFORMATION ReadFileA(LPCCH FileFullPath);
BOOL FreeFileInformation(FILE_INFORMATION FileInfo);
enum RESOLVE_FLAG
{
	RESOLVE_FLAG_DEFAULT = 0,
	RESOLVE_FLAG_API_SCHEMA_ONLY = 1,
	RESOLVE_FLAG_ENSURE_FULL_PATH = 2,
};
typedef void (NTAPI *LPFN_RTLINITUNICODESTRING)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef void (NTAPI *LPFN_RTLFREEUNICODESTRING)(PUNICODE_STRING UnicodeString);
typedef ULONG (NTAPI *LPFN_RTLNTSTATUSTODOSERROR)(NTSTATUS Status);
typedef NTSTATUS(NTAPI *LPFN_RTLDOSAPPLYFILEISOLATIONREDIRECTION_USTR)(
	IN ULONG Flags,
	IN PUNICODE_STRING OriginalName,
	IN PUNICODE_STRING Extension,
	IN OUT PUNICODE_STRING StaticString,
	IN OUT PUNICODE_STRING DynamicString,
	IN OUT PUNICODE_STRING *NewName,
	IN PULONG  NewFlags,
	IN PSIZE_T FileNameSize,
	IN PSIZE_T RequiredLength);


std::wstring StripPath(const std::wstring& FileFullPath);

DWORD ProbeSxSRedirect(std::wstring& FileFullPath);
BOOL FileExists(const std::wstring& FileFullPath);