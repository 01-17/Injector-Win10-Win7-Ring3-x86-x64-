#pragma once
#include <windows.h>
#include <iostream>
#include "ModuleHelper.h"
#include "FileHelper.h"
#include "Remoter.h"
#include <DbgHelp.h>
#pragma comment (lib, "DbgHelp.lib")

IMAGE_DOS_HEADER* ImageDosHeaderEx(PVOID BaseAddress);
IMAGE_NT_HEADERS* ImageNtHeadersEx(PVOID BaseAddress);



#define CalcDelta(Cast, DataValue1, DataValue2) (Cast)((DWORD_PTR)(DataValue1) - (DWORD_PTR)(DataValue2))


//转换为文件粒度对齐
void* RvaToPointer(ULONG RVA /*本地内存粒度对齐*/, PVOID BaseAddress /*本地文件粒度对齐*/);
ULONG GetSectionProtection(ULONG Protection);