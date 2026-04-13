#include "FileHelper.h"

FILE_INFORMATION ReadFileA(LPCCH FileFullPath)
{
	FILE_INFORMATION FileInfo;

	FileInfo.FileData = 0;
	FileInfo.FileLength = 0;

	HANDLE FileHandle = CreateFileA(FileFullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (FileHandle == INVALID_HANDLE_VALUE)
	{
		return FileInfo;
	}
	//判断文件是否有数据
	if (GetFileAttributesA(FileFullPath) & FILE_ATTRIBUTE_COMPRESSED)
	{
		//获得文件大小
		FileInfo.FileLength = GetCompressedFileSizeA(FileFullPath, NULL);   //微软压缩 
	}
	else
	{
		FileInfo.FileLength = GetFileSize(FileHandle, NULL);               //Anti
	}
	if (FileInfo.FileLength == 0)
	{
		CloseHandle(FileHandle);
		return FileInfo;
	}


	//在当前进程空间中申请内存
	unsigned char* VirtualAddress = 
		(unsigned char*)VirtualAlloc(NULL, FileInfo.FileLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (VirtualAddress == NULL)
	{
		FileInfo.FileLength = 0;
		CloseHandle(FileHandle);
		return FileInfo;
	}

	//读取文件内容到内存中
	DWORD ReturnLength = 0;
	if (ReadFile(FileHandle, VirtualAddress, FileInfo.FileLength, &ReturnLength, FALSE) == FALSE)
	{
		FileInfo.FileData = 0;
		FileInfo.FileLength = 0;
	}
	else
	{
		FileInfo.FileData = VirtualAddress;
	}
	CloseHandle(FileHandle);

	return FileInfo;
}

BOOL FreeFileInformation(FILE_INFORMATION FileInfo)
{
	if (FileInfo.FileData)
	{
		VirtualFree(FileInfo.FileData, FileInfo.FileLength, MEM_RELEASE);
		FileInfo.FileData = 0;
	}

	FileInfo.FileLength = 0;

	return (FileInfo.FileData == 0 && FileInfo.FileLength == 0);
}

std::wstring StripPath(const std::wstring& FileFullPath)
{
	if (FileFullPath.empty())
		return FileFullPath;

	auto Position = FileFullPath.rfind(L'\\');
	if (Position == FileFullPath.npos)
		Position = FileFullPath.rfind(L'/');

	if (Position != FileFullPath.npos)
		return FileFullPath.substr(Position + 1);
	else
		return FileFullPath;
}
DWORD ProbeSxSRedirect(std::wstring& FileFullPath)
{
	UNICODE_STRING v1;
	ZeroMemory(&v1, sizeof(UNICODE_STRING));
	UNICODE_STRING v2;
	ZeroMemory(&v2, sizeof(UNICODE_STRING));
	UNICODE_STRING v3;
	ZeroMemory(&v3, sizeof(UNICODE_STRING));
	PUNICODE_STRING v4 = nullptr;
	ULONG_PTR cookie = 0;
	wchar_t BufferData[255] = { 0 };

	//if (path.rfind(L".dll") != std::wstring::npos)
	//path.erase(path.rfind(L".dll"));

	HMODULE NtdllModuleBase = GetModuleHandle01("ntdll.dll");
	LPFN_RTLINITUNICODESTRING RtlInitUnicodeString = (LPFN_RTLINITUNICODESTRING)GetProcAddress01(NtdllModuleBase, "RtlInitUnicodeString");
	LPFN_RTLFREEUNICODESTRING RtlFreeUnicodeString = (LPFN_RTLFREEUNICODESTRING)GetProcAddress01(NtdllModuleBase, "RtlFreeUnicodeString");
	LPFN_RTLNTSTATUSTODOSERROR RtlNtStatusToDosError = (LPFN_RTLNTSTATUSTODOSERROR)GetProcAddress01(NtdllModuleBase, "RtlNtStatusToDosError");
	LPFN_RTLDOSAPPLYFILEISOLATIONREDIRECTION_USTR RtlDosApplyFileIsolationRedirection_Ustr =
		(LPFN_RTLDOSAPPLYFILEISOLATIONREDIRECTION_USTR)GetProcAddress01(NtdllModuleBase, "RtlDosApplyFileIsolationRedirection_Ustr");

	RtlInitUnicodeString(&v1, FileFullPath.c_str());


	//UnicodeString栈内存
	v2.Buffer = BufferData;
	v2.Length = NULL;
	v2.MaximumLength = ARRAYSIZE(BufferData);

	// Use activation context
	//if (m_hActx && m_hActx != INVALID_HANDLE_VALUE)
	//	ActivateActCtx(m_hActx, &cookie);

	// SxS resolve
	NTSTATUS Status = RtlDosApplyFileIsolationRedirection_Ustr(TRUE, &v1, NULL, &v2, &v3, &v4, NULL, NULL, NULL);

	//if (cookie != 0 && m_hActx && m_hActx != INVALID_HANDLE_VALUE)
	//	DeactivateActCtx(0, cookie);

	if (Status == STATUS_SUCCESS)
	{
		FileFullPath = v4->Buffer;
	}
	else
	{
		if (v3.Buffer)
			RtlFreeUnicodeString(&v3);
		SetLastError(RtlNtStatusToDosError(Status));
		return RtlNtStatusToDosError(Status);
	}

	if (v3.Buffer)
		RtlFreeUnicodeString(&v3);

	SetLastError(ERROR_SUCCESS);
	return ERROR_SUCCESS;
}
BOOL FileExists(const std::wstring& FileFullPath)
{
	return (GetFileAttributesW(FileFullPath.c_str()) != 0xFFFFFFFF);
}