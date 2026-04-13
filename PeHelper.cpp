#include "PeHelper.h"

IMAGE_DOS_HEADER* ImageDosHeaderEx(PVOID BaseAddress)
{
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)(BaseAddress);
	if (!ImageDosHeader)
		return NULL;
	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;
	return ImageDosHeader;
}

IMAGE_NT_HEADERS* ImageNtHeadersEx(PVOID BaseAddress)
{
	IMAGE_DOS_HEADER* ImageDosHeader = ImageDosHeaderEx(BaseAddress);
	if (ImageDosHeader == 0)
		return 0;
	IMAGE_NT_HEADERS* ImageNtHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)BaseAddress + ImageDosHeader->e_lfanew);
	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return 0;
	return ImageNtHeaders;
}


void* RvaToPointer(ULONG RVA, PVOID BaseAddress)
{
	PIMAGE_NT_HEADERS ImageNtHeaders = ImageNtHeadersEx(BaseAddress);
	if (ImageNtHeaders == 0)
		return 0;
	return ::ImageRvaToVa(ImageNtHeaders, BaseAddress, RVA, 0);
}
ULONG GetSectionProtection(ULONG Protection)
{
	ULONG Result = 0;
	if (Protection & IMAGE_SCN_MEM_NOT_CACHED)
	{
		Result |= PAGE_NOCACHE;
	}
	if (Protection & IMAGE_SCN_MEM_EXECUTE)
	{
		if (Protection & IMAGE_SCN_MEM_READ)
		{
			if (Protection & IMAGE_SCN_MEM_WRITE)
			{
				Result |= PAGE_EXECUTE_READWRITE;
			}
			
			else
			{
				Result |= PAGE_EXECUTE_READ;
			}
				
		}
		else if (Protection & IMAGE_SCN_MEM_WRITE)
		{
			Result |= PAGE_EXECUTE_WRITECOPY;
		}
			
		else
		{
			Result |= PAGE_EXECUTE;
		}
			
	}
	else if (Protection & IMAGE_SCN_MEM_READ)
	{
		if (Protection & IMAGE_SCN_MEM_WRITE)
		{
			Result |= PAGE_READWRITE;
		}
			
		else
		{
			Result |= PAGE_READONLY;
		}
			
	}
	else if (Protection & IMAGE_SCN_MEM_WRITE)
	{
		Result |= PAGE_WRITECOPY;
	}
		
	else
	{
		Result |= PAGE_NOACCESS;
	}
		

	return Result;
}
