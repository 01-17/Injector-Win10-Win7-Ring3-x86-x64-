#include "Remoter.h"



CRemoter::CRemoter()
{

	InitializeApiSchema();
}


CRemoter::~CRemoter()
{
}
void CRemoter::OnInitMember(HANDLE ProcessID, HANDLE ProcessHandle)
{

	m_ProcessHandle = ProcessHandle;
	m_ProcessID = ProcessID;

	m_Is64Bit = GetProcessPlatform(m_ProcessHandle) == WIN_VERSION_X64 ? TRUE : FALSE;
}
void CRemoter::OnFreeMember()
{

	for (size_t i = 0; i < m_CurrentInvokeInfo.StringInfoVector.size(); i++)
	{
		FreeProcessMemory(m_ProcessHandle, m_CurrentInvokeInfo.StringInfoVector[i].BufferData, m_CurrentInvokeInfo.StringInfoVector[i].BufferLength);
	}


	for (size_t i = 0; i < m_CurrentInvokeInfo.StructInfoVector.size(); i++)
	{
		FreeProcessMemory(m_ProcessHandle, m_CurrentInvokeInfo.StructInfoVector[i].BufferData, m_CurrentInvokeInfo.StructInfoVector[i].BufferLength);
	}

	m_CurrentInvokeInfo.CallingAddress = 0;
	m_CurrentInvokeInfo.ParameterInfoVector.clear();
	m_LocalShellCodeVector.clear();
}

void CRemoter::AddByteToBuffer(unsigned char DataValue)
{
	m_LocalShellCodeVector.push_back(DataValue);
}
void CRemoter::AddLongToBuffer(unsigned long DataValue)
{
	WORD LowWord = LOWORD(DataValue);
	WORD HighWord = HIWORD(DataValue);

	AddByteToBuffer(LOBYTE(LowWord));
	AddByteToBuffer(HIBYTE(LowWord));
	AddByteToBuffer(LOBYTE(HighWord));
	AddByteToBuffer(HIBYTE(HighWord));
}
void CRemoter::AddLong64ToBuffer(unsigned __int64 DataValue)
{
	unsigned long LowInt32 = (unsigned long)DataValue;
	unsigned long HighInt32 = (unsigned long)(DataValue >> 32);

	AddLongToBuffer(LowInt32);
	AddLongToBuffer(HighInt32);
}
//调用约定
void CRemoter::PushCall(CALLING_CONVENTION CallingConvention, FARPROC CallingAddress)
{

	int v1 = (int)m_CurrentInvokeInfo.ParameterInfoVector.size();

	m_CurrentInvokeInfo.CallingAddress = m_Is64Bit ? (unsigned __int64)CallingAddress : (unsigned long)CallingAddress;

	m_CurrentInvokeInfo.CallingConvention = CallingConvention;

	//64位32位的FastCall的调用
	if ((m_Is64Bit || CallingConvention == CALLING_CONVENTION_WIN64) || CallingConvention == CALLING_CONVENTION_FASTCALL)
	{
		if (m_Is64Bit)
		{
			////////////////////////////////////////////////////////////////////////////////////////////////
			//  First things first. 64 bit mandatory "shadow" space of at least 40 bytes for EVERY call   //
			//  Stack is 16 byte aligned. Every other param after rcx, rdx, r8, and r9 */				  //
			//  should be pushed onto the stack 														  //
			////////////////////////////////////////////////////////////////////////////////////////////////
			//
			//Reserve stack size (0x28 - minimal size for 4 registers and return address)
			//after call, stack must be aligned on 16 bytes boundary
			//判断参数个数来构建预留栈空间大小
			size_t Rsp = (m_CurrentInvokeInfo.ParameterInfoVector.size() > 4) ? m_CurrentInvokeInfo.ParameterInfoVector.size() * sizeof(size_t) : 0x28;
			//16字节对齐
			Rsp = BoundaryAlign(Rsp, 0x10);
			//sub  rsp, (Rsp + 8)，真正的预留指定大小的空间
			AddByteToBuffer(0x48);
			AddByteToBuffer(0x83);
			AddByteToBuffer(0xEC);
			AddByteToBuffer((unsigned char)(Rsp + 8));

			//如果有参数
			if (v1 > 0)
			{
				for (int i = 0; i < PARAMETER_INDEX_MAX; i++)
				{
					if (m_CurrentInvokeInfo.ParameterInfoVector.size() == 0)
					{
						break;
					}
					if (_PARAMETER_TYPE_STRING(m_CurrentInvokeInfo.ParameterInfoVector[0].ParameterType))
					{
						LoadStringParameter64(m_CurrentInvokeInfo.ParameterInfoVector[0], (PARAMETER_INDEX)i);
					}
					else
					{
						unsigned __int64 ParameterData = *(unsigned __int64*)m_CurrentInvokeInfo.ParameterInfoVector[0].ParameterData; // rcx param
						LoadParameter64(ParameterData, (PARAMETER_INDEX)i);
					}

					m_CurrentInvokeInfo.ParameterInfoVector.erase(m_CurrentInvokeInfo.ParameterInfoVector.begin());
				}
			}

			PushAllParameters(true);

			//
			//Call function address, and clean stack
			//
			//mov  r13, CallingAddress
			//call r13
			AddByteToBuffer(0x49);
			AddByteToBuffer(0xBD);		//mov r13,
			AddLong64ToBuffer(m_CurrentInvokeInfo.CallingAddress); // CallingAddress
			AddByteToBuffer(0x41);
			AddByteToBuffer(0xFF);		//call
			AddByteToBuffer(0xD5);		//r13
			//Clean stack
			//add rsp, (Rsp + 8)
			AddByteToBuffer(0x48);
			AddByteToBuffer(0x83);
			AddByteToBuffer(0xC4);
			AddByteToBuffer((unsigned char)(Rsp + 8));
		}
		else //32 bit
		{
			if (v1 == 0)  //无参数的Fastcall就是Stdcall调用约定
			{
				PushCall(CALLING_CONVENTION_STDCALL, CallingAddress); //is actually a stdcall
				return;
			}
			else if (v1 == 1)//一个参数使用ecx寄存器
			{
				//常量赋值运算
				unsigned long Ecx = *(unsigned long*)m_CurrentInvokeInfo.ParameterInfoVector[0].ParameterData;
				//mov ecx, Ecx
				AddByteToBuffer(0xB9);
				AddLongToBuffer(Ecx);

				m_CurrentInvokeInfo.ParameterInfoVector.erase(m_CurrentInvokeInfo.ParameterInfoVector.begin()); //erase ecx param

				PushCall(CALLING_CONVENTION_STDCALL, CallingAddress); //is actually a stdcall

				return;
			}
			else // fastcall
			{
				unsigned long Ecx = *(unsigned long *)m_CurrentInvokeInfo.ParameterInfoVector[0].ParameterData; // ecx param
				unsigned long Edx = *(unsigned long *)m_CurrentInvokeInfo.ParameterInfoVector[1].ParameterData; // edx param
				//mov ecx, Ecx
				AddByteToBuffer(0xB9);
				AddLongToBuffer(Ecx);
				//mov edx, Edx
				AddByteToBuffer(0xBA);
				AddLongToBuffer(Edx);

				m_CurrentInvokeInfo.ParameterInfoVector.erase(m_CurrentInvokeInfo.ParameterInfoVector.begin()); // erase ecx (first) param
				m_CurrentInvokeInfo.ParameterInfoVector.erase(m_CurrentInvokeInfo.ParameterInfoVector.begin()); // erase edx (second) param

				//从右至左
				PushAllParameters(TRUE);

				//mov ebx, CallingAddress
				AddByteToBuffer(0xBB);
				AddLongToBuffer((unsigned long)m_CurrentInvokeInfo.CallingAddress);
				//call ebx
				AddByteToBuffer(0xFF);
				AddByteToBuffer(0xD3);
			}
		}
	}
	else if (CallingConvention == CALLING_CONVENTION_CDECL)
	{

		//计算参数列表的空间 最后要回收参数列表栈
		int Esp = (v1 * 4);

		BOOL IsRightToLeft = TRUE;
		PushAllParameters(IsRightToLeft);

		//mov eax, CallingAddress
		AddByteToBuffer(0xB8);
		AddLongToBuffer((unsigned long)m_CurrentInvokeInfo.CallingAddress);
		//call eax
		AddByteToBuffer(0xFF);
		AddByteToBuffer(0xD0);

		if (Esp != 0)
		{
			BOOL IsUseByte = (Esp <= 0xFF /* 255 */);
			if (IsUseByte)
			{
				//add esp, (byte)Esp
				AddByteToBuffer(0x83); //0x83 is for adding a byte value
				AddByteToBuffer(0xC4);
				AddByteToBuffer((unsigned char)Esp);
			}
			else
			{
				//add esp, Esp
				AddByteToBuffer(0x81); //0x81 is for adding a long value
				AddByteToBuffer(0xC4);
				AddLongToBuffer(Esp);
			}
		}
	}
	else if (CallingConvention == CALLING_CONVENTION_STDCALL)
	{

		BOOL  IsRightToLeft = TRUE;   //压参顺序
		PushAllParameters(IsRightToLeft);

		//mov eax, CallingAddress            
		//call eax
		AddByteToBuffer(0xB8);			//mov eax,						
		AddLongToBuffer((unsigned long)m_CurrentInvokeInfo.CallingAddress); // CallingAddress	
		AddByteToBuffer(0xFF);			//call
		AddByteToBuffer(0xD0);			//eax
	}
	else if (CallingConvention == CALLING_CONVENTION_THISCALL)
	{
		if (v1 == 0) //no params...
		{
			//没有参数不用处理
		}

		//first parameter of __thiscall is ALWAYS ECX. ALWAYS.
		//the parameter type should also be PARAM_TYPE_POINTER
		if (m_CurrentInvokeInfo.ParameterInfoVector[0].ParameterType != PARAMETER_TYPE_POINTER)
		{
			//参数是不合法但是不用退出 
		}

		void *This = m_CurrentInvokeInfo.ParameterInfoVector[0].ParameterData;
		if (This == NULL)
		{
			//参数是不合法但是不用退出 
		}

		//mov ecx, This
		AddByteToBuffer(0x8B); // mov ecx,
		AddByteToBuffer(0x0D);
		AddLongToBuffer((unsigned long)This); //This

		//now we need to remove the first parameter from the vector, so when we execute the
		//parameter iteration function it is not included.....
		m_CurrentInvokeInfo.ParameterInfoVector.erase(m_CurrentInvokeInfo.ParameterInfoVector.begin());

		//从右至左压入剩下的参数
		PushAllParameters(TRUE);

		AddByteToBuffer(0xB8);			//mov eax, 
		AddLongToBuffer((unsigned long)m_CurrentInvokeInfo.CallingAddress); //CallingAddress
		AddByteToBuffer(0xFF);			//call
		AddByteToBuffer(0xD0);			//eax
	}


	m_CurrentInvokeInfo.ParameterInfoVector.clear();   //??? 内存有没有销毁
	m_CurrentInvokeInfo.CallingAddress = NULL;
}
//参数类型
void CRemoter::PushAllParameters(BOOL IsRightToLeft)
{
	//判断有无参数
	if (m_CurrentInvokeInfo.ParameterInfoVector.size() == 0)
	{
		return;
	}

	vector<PARAMETER_INFORMATION> v2;

	if (IsRightToLeft == FALSE)
	{
	}
	else
	{
		//从右至左
		if (m_CurrentInvokeInfo.ParameterInfoVector.size() == 1)
		{
			v2.push_back(m_CurrentInvokeInfo.ParameterInfoVector.at(0));
		}
		else
		{
			int Start = (int)m_CurrentInvokeInfo.ParameterInfoVector.size() - 1;
			while (Start != -1)
			{
				//倒取数据
				v2.push_back(m_CurrentInvokeInfo.ParameterInfoVector.at(Start));

				Start--;
			}
		}
	}

	for (int i = 0; i < (int)v2.size(); i++)
	{
		PARAMETER_INFORMATION* ParameterInfo = &v2[i];
		if (ParameterInfo == NULL)
		{
			continue;
		}
		if (ParameterInfo->ParameterData == NULL)
		{
			// push 0
			AddByteToBuffer(0x68);	// push
			AddLongToBuffer(0x00);	// 0
			continue;
		}

		switch (ParameterInfo->ParameterType)
		{
		case PARAMETER_TYPE_DOUBLE:		//8Bits压参
		case PARAMETER_TYPE_INT64:
		{

			break;
		}
		case PARAMETER_TYPE_POINTER:
		{
			if (ParameterInfo->ParameterData)
			{
				unsigned __int64 ParameterData = *(unsigned __int64*)ParameterInfo->ParameterData;

				if (m_Is64Bit)
				{
					// mov rax, ulParam
					AddByteToBuffer(0x48);
					AddByteToBuffer(0xB8);
					AddLong64ToBuffer(ParameterData);
					// push rax
					AddByteToBuffer(0x50);
				}
				else
				{
					unsigned long ParameterData = *(unsigned long *)ParameterInfo->ParameterData;
					// push ulParam
					AddByteToBuffer(0x68);
					AddLongToBuffer(ParameterData);
				}
			}
			else
			{
				// if it is PARAM_TYPE_POINTER with a NULL pointer
				// we don't want to crash
				// push 0
				AddByteToBuffer(0x68);
				AddLongToBuffer(0x00);
			}
			break;
		}
		case PARAMETER_TYPE_SHORT:		//4Bits压参
		case PARAMETER_TYPE_INT:
		case PARAMETER_TYPE_FLOAT:
		{
			if (ParameterInfo->ParameterData)
			{
				unsigned long ParameterData = *(unsigned long *)ParameterInfo->ParameterData;

				//push ParameterData
				AddByteToBuffer(0x68);
				AddLongToBuffer(ParameterData);
			}
			else
			{

				//push 0
				AddByteToBuffer(0x68);
				AddLongToBuffer(NULL);
			}

			break;
		}
		case PARAMETER_TYPE_BYTE:
		{
			unsigned char ParameterData = *(unsigned char*)ParameterInfo->ParameterData;

			//push ParameterData
			AddByteToBuffer(0x6A);
			AddByteToBuffer(ParameterData);

			break;
		}
		case PARAMETER_TYPE_BOOL:
		{
			bool IsParameterData = *(bool*)ParameterInfo->ParameterData;

			unsigned char ParameterData = (IsParameterData) ? 1 : 0;

			//push ParameterData
			AddByteToBuffer(0x6A);
			AddByteToBuffer(ParameterData);

			break;
		}
		case PARAMETER_TYPE_STRING:
		{

			break;
		}
		case PARAMETER_TYPE_WSTRING:
		{
			wchar_t *ParameterData = (wchar_t *)ParameterInfo->ParameterData;


			STRING_INFORMATION StringInfo;

			StringInfo.BufferLength = (wcslen(ParameterData) * 2) + 1;
			StringInfo.BufferData = CommitProcessMemory(m_ProcessHandle, ParameterData, StringInfo.BufferLength);

			if (StringInfo.BufferData == NULL)
			{

				continue;
			}

			m_CurrentInvokeInfo.StringInfoVector.push_back(StringInfo);

			AddByteToBuffer(0x68);
			AddLongToBuffer((unsigned long)StringInfo.BufferData);
			break;
		}
		case PARAMETER_TYPE_UNICODE_STRING:
		{
			UNICODE_STRING ParameterData = *(UNICODE_STRING*)ParameterInfo->ParameterData;

			STRING_INFORMATION StringInfo;
			StringInfo.BufferLength = (ULONG)(ParameterData.MaximumLength * 2) + 1;
			StringInfo.BufferData = CommitProcessMemory(m_ProcessHandle, ParameterData.Buffer, StringInfo.BufferLength);
			//在目标进程中申请一个字符串内存并将ParameterData.Buffer中的数据写入目标进程中并返回地址到StringInfo.BufferData
			if (StringInfo.BufferData == NULL)
			{
				return;
			}

			m_CurrentInvokeInfo.StringInfoVector.push_back(StringInfo);

			UNICODE_STRING v1;
			v1.Buffer = (wchar_t*)StringInfo.BufferData;   //把目标进程中标识那个字符串的内存放入到一个UnicodeString中
			v1.Length = ParameterData.Length;
			v1.MaximumLength = ParameterData.MaximumLength;

			STRUCT_INFORMATION v2;
			v2.BufferLength = (ULONG)sizeof(UNICODE_STRING);
			v2.BufferData = CommitProcessMemory(m_ProcessHandle, &v1, v2.BufferLength);
			//在目标进程中申请一个UnicodeString内存并将v1中的数据写入目标进程中并返回地址到v2.BufferData


			m_CurrentInvokeInfo.StructInfoVector.push_back(v2);

			//push v2.BufferData
			AddByteToBuffer(0x68);
			AddLongToBuffer((unsigned long)v2.BufferData);
		}
		default:
		{

			break;
		}

		}
	}
}
void CRemoter::PushParameter(PARAMETER_TYPE ParameterType, void *ParameterData)
{
	PARAMETER_INFORMATION ParameterInfo;

	ParameterInfo.ParameterType = ParameterType;
	ParameterInfo.ParameterData = ParameterData;

	m_CurrentInvokeInfo.ParameterInfoVector.push_back(ParameterInfo);
}
void CRemoter::PushInt(int DataValue)
{
	int *v1 = new int;
	*v1 = DataValue;
	PushParameter(PARAMETER_TYPE_INT, v1);
}
void CRemoter::PushInt64(__int64 DataValue)
{
	__int64 *v1 = new __int64;
	*v1 = DataValue;
	PushParameter(PARAMETER_TYPE_INT64, v1);
}
void CRemoter::PushUInt64(unsigned __int64 DataValue)
{
	unsigned __int64 *v1 = new unsigned __int64;
	*v1 = DataValue;
	PushParameter(PARAMETER_TYPE_INT64, v1);
}
void CRemoter::PushPointer(void* DataValue)
{
	PushParameter(PARAMETER_TYPE_POINTER, DataValue);
}
void CRemoter::PushUnicodeString(const wchar_t* DataValue)
{
	PushParameter(PARAMETER_TYPE_WSTRING, (void*)DataValue);
}
void CRemoter::PushUnicodeStringStructure(UNICODE_STRING* DataValue)
{
	PushParameter(PARAMETER_TYPE_UNICODE_STRING, (void*)DataValue);
}

void CRemoter::BeginCall64()
{
	//被调函数要将4个寄存器的值保存到内存中

	//mov    QWORD PTR [rsp+0x8],rcx
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x89);
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x24);
	AddByteToBuffer(1 * sizeof(size_t));
	//mov    QWORD PTR [rsp+0x10],rdx
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x89);
	AddByteToBuffer(0x54);
	AddByteToBuffer(0x24);
	AddByteToBuffer(2 * sizeof(size_t));
	// mov    QWORD PTR [rsp+0x18],r8
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x89);
	AddByteToBuffer(0x44);
	AddByteToBuffer(0x24);
	AddByteToBuffer(3 * sizeof(size_t));
	//mov    QWORD PTR [rsp+0x20],r9
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x89);
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x24);
	AddByteToBuffer(4 * sizeof(size_t));
}
void CRemoter::EndCall64()
{
	//Restore registers and return

	// mov    rcx,QWORD PTR [rsp+0x8]
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x8B);
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x24);
	AddByteToBuffer(1 * sizeof(size_t));
	// mov    rdx,QWORD PTR [rsp+0x10]
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x8B);
	AddByteToBuffer(0x54);
	AddByteToBuffer(0x24);
	AddByteToBuffer(2 * sizeof(size_t));
	// mov    r8,QWORD PTR [rsp+0x18]
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x8B);
	AddByteToBuffer(0x44);
	AddByteToBuffer(0x24);
	AddByteToBuffer(3 * sizeof(size_t));
	// mov    r9,QWORD PTR [rsp+0x20]
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x8B);
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x24);
	AddByteToBuffer(4 * sizeof(size_t));
	// ret
	AddByteToBuffer(0xC3);
}
void CRemoter::LoadStringParameter64(PARAMETER_INFORMATION ParameterInfo, PARAMETER_INDEX ParameterIndex)
{
	if (ParameterInfo.ParameterType == PARAMETER_TYPE_STRING)
	{
		char* ParameterData = (char*)ParameterInfo.ParameterData;

		STRING_INFORMATION StringInfo;
		StringInfo.BufferLength = (ULONG)(strlen(ParameterData) + 1);
		StringInfo.BufferData = CommitProcessMemory(m_ProcessHandle, ParameterData, StringInfo.BufferLength);  //目标进程空间中申请内存复制数据
		if (StringInfo.BufferData == NULL)
		{
			return;
		}

		m_CurrentInvokeInfo.StringInfoVector.push_back(StringInfo);
		if (m_Is64Bit)
		{
			LoadParameter64((unsigned __int64)StringInfo.BufferData, ParameterIndex);  //将目标进程中申请内存的地址放入到寄存器中
		}
		else
		{
			//不用处理
		}
	}
	else if (ParameterInfo.ParameterType == PARAMETER_TYPE_WSTRING)
	{
		wchar_t *ParameterData = (wchar_t *)ParameterInfo.ParameterData;

		STRING_INFORMATION StringInfo;
		StringInfo.BufferLength = (ULONG)(wcslen(ParameterData) * 2) + 1;
		StringInfo.BufferData = CommitProcessMemory(m_ProcessHandle, ParameterData, StringInfo.BufferLength);
		if (StringInfo.BufferData == NULL)
		{

			return;
		}

		m_CurrentInvokeInfo.StringInfoVector.push_back(StringInfo);

		if (m_Is64Bit)
		{
			LoadParameter64((unsigned __int64)StringInfo.BufferData, ParameterIndex);
		}
		else
		{
			//不用处理
		}
	}
	else if (ParameterInfo.ParameterType == PARAMETER_TYPE_UNICODE_STRING)
	{
		UNICODE_STRING ParameterData = *(UNICODE_STRING*)ParameterInfo.ParameterData;

		STRING_INFORMATION StringInfo;
		StringInfo.BufferLength = (ULONG)(ParameterData.MaximumLength * 2) + 1;
		StringInfo.BufferData = CommitProcessMemory(m_ProcessHandle, ParameterData.Buffer, StringInfo.BufferLength);
		if (StringInfo.BufferData == NULL)
		{
			return;
		}

		m_CurrentInvokeInfo.StringInfoVector.push_back(StringInfo);

		UNICODE_STRING v1;
		v1.Buffer = (wchar_t*)StringInfo.BufferData;
		v1.Length = ParameterData.Length;
		v1.MaximumLength = ParameterData.MaximumLength;

		STRUCT_INFORMATION StructInfo;
		StructInfo.BufferLength = (ULONG)sizeof(UNICODE_STRING);
		StructInfo.BufferData = CommitProcessMemory(m_ProcessHandle, &v1, StructInfo.BufferLength);

		m_CurrentInvokeInfo.StructInfoVector.push_back(StructInfo);

		if (m_Is64Bit)
		{
			LoadParameter64((unsigned __int64)StructInfo.BufferData, ParameterIndex);
		}
		else
		{
		}
	}
}
BOOL CRemoter::LoadParameter64(unsigned __int64 ParameterData, PARAMETER_INDEX ParameterIndex)
{
	switch (ParameterIndex)
	{
	case PARAMETER_INDEX_RCX:
	{
		//mov  rcx, pparam
		AddByteToBuffer(0x48);
		AddByteToBuffer(0xB9);
		AddLong64ToBuffer(ParameterData);

		break;
	}
	case PARAMETER_INDEX_RDX:
	{
		//mov  rdx, ulRdxParam
		AddByteToBuffer(0x48);
		AddByteToBuffer(0xBA);
		AddLong64ToBuffer(ParameterData);

		break;
	}
	case PARAMETER_INDEX_R8:
	{
		//mov  r8, ulR8Param
		AddByteToBuffer(0x49);
		AddByteToBuffer(0xB8);
		AddLong64ToBuffer(ParameterData);

		break;
	}
	case PARAMETER_INDEX_R9:
	{
		//mov  r9, ulR9Param
		AddByteToBuffer(0x49);
		AddByteToBuffer(0xB9);
		AddLong64ToBuffer(ParameterData);

		break;
	}
	default:
		return FALSE;
	}
	return TRUE;
}


HMODULE CRemoter::LoadLibraryByPathA(LPCCH ModuleFullPath, ULONG Flags/*= NULL*/)
{
	WCHAR v1[MAX_PATH] = { 0 };
	size_t ReturnLength = 0;
	mbstowcs_s(&ReturnLength, v1, ModuleFullPath, MAX_PATH);
	return LoadLibraryByPathW(v1, Flags);
}
HMODULE CRemoter::LoadLibraryByPathW(LPCWCH ModuleFullPath, ULONG Flags/*= NULL*/)
{
	if (ModuleFullPath == NULL)
	{
		return NULL;
	}

	//目标进程中获取LoadLibraryW函数地址
	FARPROC LoadLibraryW = (FARPROC)GetProcessProcAddressW(GetProcessModuleHandleW(m_ProcessHandle,L"kernel32.dll"), L"LoadLibraryW");

	if (LoadLibraryW == NULL)
	{
		return NULL;
	}
	//目标进程中申请作为返回值的内存
	PVOID ReturnPointerValue = AllocateProcessMemory(m_ProcessHandle,sizeof(size_t));
	//目标进程
	if (m_Is64Bit)
	{
		//push的ShellCode到Vector结构体，有扩容机制动态存储
		BeginCall64();
		//push参数到ParameterInfoVector结构
		PushUnicodeString(ModuleFullPath);
		
		PushCall(CALLING_CONVENTION_WIN64, LoadLibraryW);

		                           
		//mov [ReturnPointerValue], rax
		AddByteToBuffer(0x48);
		AddByteToBuffer(0xA3);
		AddLong64ToBuffer((unsigned __int64)ReturnPointerValue);
		//Restore RCX, RDX, R8 and R9 from stack and return
		EndCall64();
	}
	else
	{

		PushUnicodeString(ModuleFullPath);

		PushCall(CALLING_CONVENTION_STDCALL, LoadLibraryW);

		//mov ReturnPointerValue, eax
		AddByteToBuffer(0xA3);
		AddLongToBuffer((DWORD)ReturnPointerValue);

		//xor eax, eax
		AddByteToBuffer(0x33);
		AddByteToBuffer(0xC0);

		//retn 4
		AddByteToBuffer(0xC2);
		AddByteToBuffer(0x04);
		AddByteToBuffer(0x00);

	}
	if (ExecuteProcessMemoryData(m_ProcessHandle,m_LocalShellCodeVector) == FALSE)
	{
		FreeProcessMemory(m_ProcessHandle,ReturnPointerValue, sizeof(size_t));

		OnFreeMember();
		return NULL;
	}

	HMODULE ModuleHandle = 0;
	if (ReadProcessMemory(m_ProcessHandle, ReturnPointerValue, &ModuleHandle, sizeof(HMODULE), NULL))
	{
		FreeProcessMemory(m_ProcessHandle,ReturnPointerValue, sizeof(size_t));
	}
	else
	{
		FreeProcessMemory(m_ProcessHandle,ReturnPointerValue, sizeof(size_t));
		if (ModuleHandle == 0)
		{
			ModuleHandle = GetProcessModuleHandleW(m_ProcessHandle,ModuleFullPath);
		}
		
	}
	OnFreeMember();
	return ModuleHandle;

}
HMODULE CRemoter::LoadLibraryByPathIntoMemoryW(LPCWCH ModuleFullPath, BOOL IsPEHeader)
{
	CHAR v1[MAX_PATH] = { 0 };
	size_t ReturnLength = 0;
	wcstombs_s(&ReturnLength, v1, ModuleFullPath, MAX_PATH);
	return LoadLibraryByPathIntoMemoryA(v1, IsPEHeader);
}
HMODULE CRemoter::LoadLibraryByPathIntoMemoryA(LPCCH ModuleFullPath, BOOL IsPEHeader)
{
	HMODULE ModuleBase = NULL;

	//读取PE文件数据到内存中
	FILE_INFORMATION FileInfo = ReadFileA(ModuleFullPath);
	if (FileInfo.IsValid() == FALSE)
	{
		return NULL;
	}

	ModuleBase = LoadLibraryFromMemory(FileInfo.FileData, FileInfo.FileLength, IsPEHeader);
	if (FreeFileInformation(FileInfo) == FALSE)
	{

	}

	return ModuleBase;
}
HMODULE CRemoter::LoadLibraryFromMemory(PVOID FileData, DWORD FileLength, BOOL IsPEHeader)
{

	IMAGE_NT_HEADERS* ImageNtHeaders = ImageNtHeadersEx(FileData);
	if (ImageNtHeaders == NULL)
	{
		return NULL;
	}

	if (ImageNtHeaders->FileHeader.NumberOfSections == 0)  //.txt  .data
	{
		return NULL;
	}

	if (m_Is64Bit)
	{
		DWORD Status = CreateProcessProcedureCallEnvironment();   //创建一个具有可提醒IO的线程和一个命名
		if (Status != ERROR_SUCCESS)
		{
			return NULL;
		}

	}
	size_t v1 = (!IsPEHeader) ? ((size_t)-1) : 0;   //无符号长整形
	size_t v2 = 0;
	
	
	PIMAGE_SECTION_HEADER ImageSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);
	for (size_t i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; ++i)
	{
		if (!ImageSectionHeader[i].Misc.VirtualSize)
		{
			//节中的真实数据为空
			continue;
		}
		if (ImageSectionHeader[i].VirtualAddress < v1)
		{
			//当前节的开始
			v1 = ImageSectionHeader[i].VirtualAddress;
		}
			
		if ((ImageSectionHeader[i].VirtualAddress + ImageSectionHeader[i].Misc.VirtualSize) > v2)
		{
			//当前节的末尾
			v2 = ImageSectionHeader[i].VirtualAddress + ImageSectionHeader[i].Misc.VirtualSize;
		}
		
	}
	//获取整个PE文件的大小
	size_t RemoteImageSize = v2 - v1;

	if ((ImageNtHeaders->OptionalHeader.ImageBase % 4096) != 0)
	{
		//没有对齐粒度
		return NULL;
	}
	
	/*if (ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size
		&& ::ImageDirectoryEntryToData(FileData, TRUE, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, NULL))
	{
		//存在COM/CLR数据
		return NULL;
	}*/

	
	//在目标进程空间中申请内存
	void* RemoteImageBase = AllocateProcessMemory(m_ProcessHandle,RemoteImageSize);
	if (RemoteImageBase == NULL)
	{
		return NULL;
	}
	//导入表 loadLibrary
	if (FixProcessImportTable(FileData, RemoteImageBase) == FALSE)
	{
		FreeProcessMemory(m_ProcessHandle,RemoteImageBase, RemoteImageSize);
		return NULL;
	}
	//延迟导入表
	if (FixProcessDelayedImportTable(FileData, RemoteImageBase) == FALSE)
	{
		FreeProcessMemory(m_ProcessHandle,RemoteImageBase, RemoteImageSize);
		return NULL;
	}
	//重定向表
	if (FixProcessBaseRelocationTable(FileData, RemoteImageBase) == FALSE)
	{
		FreeProcessMemory(m_ProcessHandle,RemoteImageBase, RemoteImageSize);
		return NULL;
	}
	//节表属性
	if (FixProcessSections(FileData, RemoteImageBase, IsPEHeader) == FALSE)
	{
		
	}
	if (m_Is64Bit && IsPEHeader)
	{

	}
	//TLSCallBack
	if (ExecuteProcessTLSCallBack(FileData, RemoteImageBase) == FALSE)
	{
		FreeProcessMemory(m_ProcessHandle,RemoteImageBase, RemoteImageSize);
		return NULL;
	}
	InitializeCookie(FileData, RemoteImageBase);

	//获得OEP
	if (ImageNtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		FARPROC DllMain = MakePtr(FARPROC, RemoteImageBase, ImageNtHeaders->OptionalHeader.AddressOfEntryPoint);


		if (CallEntryPoint(RemoteImageBase, DllMain) == FALSE)
		{

		}
		else
		{

		}
	}
	else
	{

	}
	return (HMODULE)RemoteImageBase;

}
FARPROC CRemoter::GetProcessProcAddressA(HMODULE ModuleBase, LPCCH Keyword)
{
	void* v1 = (void*)ModuleBase;

	IMAGE_DOS_HEADER ImageDosHeader = { 0 };
	IMAGE_NT_HEADERS ImageNtHeaders = { 0 };
	IMAGE_EXPORT_DIRECTORY* ImageExportDirectory = { 0 };
	void* FunctionAddress = NULL;

	SIZE_T ReturnLength = 0;
	//读取目标进程v1地址处的数据到结构体IMAGE_DOS_HEADER中
	ReadProcessMemory(m_ProcessHandle, (BYTE*)v1, &ImageDosHeader, sizeof(IMAGE_DOS_HEADER), &ReturnLength);

	//判断PE文件是否有效
	if (ImageDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}
	//读取目标进程中XXX模块的IMAGE_NT_HEADERS
	ReadProcessMemory(m_ProcessHandle, (BYTE*)v1 + ImageDosHeader.e_lfanew, &ImageNtHeaders, sizeof(IMAGE_NT_HEADERS), &ReturnLength);
	if (ImageNtHeaders.Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}
	size_t ImageExportDirectoryRVA = ImageNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	//判断是否存在导出表
	if (ImageExportDirectoryRVA)
	{
		DWORD v2 = ImageNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		ImageExportDirectory = (IMAGE_EXPORT_DIRECTORY*)malloc(v2);
		ReadProcessMemory(m_ProcessHandle, (BYTE*)v1 + ImageExportDirectoryRVA, ImageExportDirectory, v2, &ReturnLength);

		//定位以下3个成员在目标进程中的RVA
		WORD  *AddressOfNameOrdinals = (WORD*)(ImageExportDirectory->AddressOfNameOrdinals + (size_t)ImageExportDirectory - ImageExportDirectoryRVA);
		DWORD *AddressOfNames = (DWORD*)(ImageExportDirectory->AddressOfNames + (size_t)ImageExportDirectory - ImageExportDirectoryRVA);
		DWORD *AddressOfFunctions = (DWORD*)(ImageExportDirectory->AddressOfFunctions + (size_t)ImageExportDirectory - ImageExportDirectoryRVA);


		for (DWORD i = 0; i < ImageExportDirectory->NumberOfFunctions; ++i)
		{
			WORD Ordinal = 0xFFFF;
			char *v3 = NULL;

			//索引导出
			if ((size_t)Keyword <= 0xFFFF)
			{
				Ordinal = (WORD)i;
			}
			else if ((size_t)Keyword > 0xFFFF && i < ImageExportDirectory->NumberOfNames)
			{
				v3 = (char*)(AddressOfNames[i] + (size_t)ImageExportDirectory - ImageExportDirectoryRVA);
				Ordinal = (WORD)AddressOfNameOrdinals[i];
			}
			else
				return 0;

			if (((size_t)Keyword <= 0xFFFF && (WORD)Keyword == (Ordinal + ImageExportDirectory->Base)) ||
				((size_t)Keyword > 0xFFFF && strcmp(v3, Keyword) == 0))
			{
				FunctionAddress = (void*)((size_t)v1 + AddressOfFunctions[Ordinal]);  //测试
				//函数转发器
				if ((size_t)FunctionAddress >= (size_t)v1 + ImageExportDirectoryRVA && (size_t)FunctionAddress <= (size_t)v1 + ImageExportDirectoryRVA + v2)
				{
					char v4[255] = { 0 };
					ReadProcessMemory(m_ProcessHandle, FunctionAddress, v4, sizeof(v4), &ReturnLength);

					std::string v5(v4);

					std::string v6 = v5.substr(0, v5.find(".")) + ".dll";
					std::string v7 = v5.substr(v5.find(".") + 1, v7.npos);

					//在目标进程空间中寻找该模块
					HMODULE v8 = GetProcessModuleHandleA(m_ProcessHandle, v6.c_str());
					if (v8 == NULL)
					{
						//加载模块
						v8 = LoadLibraryByPathA(v6.c_str());
					}

					if (v7.find("#") == 0)    //索引
						return GetProcessProcAddressA(v8, (const char*)atoi(v7.c_str() + 1));
					else                      //函数名称
						return GetProcessProcAddressA(v8, v7.c_str());
				}

				break;
			}
		}
		free(ImageExportDirectory);
	}

	return (FARPROC)FunctionAddress;
}
FARPROC CRemoter::GetProcessProcAddressW(HMODULE ModuleBase, LPCWCH Keyword)
{
	char v1[MAX_PATH] = { 0 };
	size_t ReturnLength = 0;
	wcstombs_s(&ReturnLength, v1, Keyword, MAX_PATH);
	return GetProcessProcAddressA(ModuleBase, v1);
}
DWORD CRemoter::CreateProcessProcedureCallEnvironment(BOOL IsThread /*= FALSE*/)
{
	DWORD IsOk = FALSE;
	DWORD Status = ERROR_SUCCESS;
	DWORD ThreadID = 0;
	
	
	//申请内存
	if (m_RemoteWorkerCode == NULL)
	{
		m_RemoteWorkerCode = AllocateProcessMemory(m_ProcessHandle,0x1000);
	}
		

	//目标进程空间创建一个线程
	if (IsThread == FALSE)
	{
		ThreadID = CreateProcessWorkerThread();   //启动一个具有可提醒IO的线程
	}
	//目标进程空间创建一个命名事件
	Status = CreateProcessAPCEvent(ThreadID);    //
	if (ThreadID == 0 || Status == FALSE)
	{
		IsOk = GetLastError();
	}

	m_WorkerThreadID = (HANDLE)ThreadID;

	return IsOk;
}
DWORD CRemoter::CreateProcessWorkerThread()
{
	DWORD ThreadID = 0;
	int v2 = 4 * sizeof(size_t); // 4 int64 values on top of thread. Kinda likea mini stack

	
	//在目标进程中创建一个线程
	if (!m_WorkerThreadHandle)
	{
		/*
		for(;;)
		SleepEx(5, TRUE);

		ExitThread(SetEvent(m_hWaitEvent));
		*/
		BeginCall64();

		PushUInt64(5);
		PushUInt64(TRUE);
		PushCall(CALLING_CONVENTION_WIN64, (FARPROC)SleepEx);

		//Relative jump back RIP 41 bytes
		AddByteToBuffer(0xEB);   //近跳转
		AddByteToBuffer(0xD5);
		ExitThreadWithStatus();

		EndCall64();


		unsigned char *v1 = new unsigned char[m_LocalShellCodeVector.size()];

		for (int i = 0; i < (int)m_LocalShellCodeVector.size(); i++)
			v1[i] = m_LocalShellCodeVector[i];

		m_RemoteWorkerCodeThreadLength = m_LocalShellCodeVector.size();
		
		m_RemoteWorkerCodeThread = (void*)((size_t)m_RemoteWorkerCode + v2);

		//向目标进程中写入v1数据,也就是我们上面的shellCode
		BOOL IsOk = WriteProcessMemory(m_ProcessHandle, (void*)m_RemoteWorkerCodeThread, v1, m_RemoteWorkerCodeThreadLength, NULL);
		if (IsOk == FALSE)
		{
			delete[] v1;

			OnFreeMember();
			return NULL;
		}

		delete[] v1;

	
		//创建一个远程线程执行
		/*
		0:016> u 0x00000274eda10020 l 50
		00000274`eda10020 48894c2408      mov     qword ptr [rsp+8],rcx
		00000274`eda10025 4889542410      mov     qword ptr [rsp+10h],rdx
		00000274`eda1002a 4c89442418      mov     qword ptr [rsp+18h],r8
		00000274`eda1002f 4c894c2420      mov     qword ptr [rsp+20h],r9
		00000274`eda10034 4883ec38        sub     rsp,38h
		00000274`eda10038 48b90500000000000000 mov rcx,5
		00000274`eda10042 48ba0100000000000000 mov rdx,1
		00000274`eda1004c 49bdd0247629fb7f0000 mov r13,offset KERNEL32!SleepEx (00007ffb`297624d0)
		00000274`eda10056 41ffd5          call    r13
		00000274`eda10059 4883c438        add     rsp,38h
		00000274`eda1005d ebd5            jmp     00000274`eda10034
		00000274`eda1005f 4889c1          mov     rcx,rax
		00000274`eda10062 49bdc0771d2afb7f0000 mov r13,offset ntdll!RtlExitUserThread (00007ffb`2a1d77c0)
		00000274`eda1006c 41ffd5          call    r13
		00000274`eda1006f 488b4c2408      mov     rcx,qword ptr [rsp+8]
		00000274`eda10074 488b542410      mov     rdx,qword ptr [rsp+10h]
		00000274`eda10079 4c8b442418      mov     r8,qword ptr [rsp+18h]
		00000274`eda1007e 4c8b4c2420      mov     r9,qword ptr [rsp+20h]
		00000274`eda10083 c3              ret     
		*/


		m_WorkerThreadHandle = NtCreateThreadEx(m_ProcessHandle, (LPTHREAD_START_ROUTINE)m_RemoteWorkerCodeThread, m_RemoteWorkerCode, &ThreadID);
		OnFreeMember();
		return ThreadID;
	}
	else
	{
		//线程已经存在
		return GetThreadId(m_WorkerThreadHandle);
	}
		
}
BOOL CRemoter::CreateProcessAPCEvent(DWORD ThreadID)
{
	if (!m_WaitEventHandle)
	{
		size_t Status = ERROR_SUCCESS;
		void* v2 = NULL;
		wchar_t EventName[64] = { 0 };
		size_t EventNameLength = sizeof(EventName);


		/*
		HANDLE CreateEvent(  LPSECURITY_ATTRIBUTES lpEventAttributes, // SD
		 BOOL bManualReset,                       // reset type
		 BOOL bInitialState,                      // initial state
		 LPCTSTR lpName                           // object name);	
		*/


		//为命名事件起一个名字，用GUID起，128位的唯一数
		//EventName = 0x0000001f4ccfe7b0 L"_Event_0x37D8_0xD9396BB"
		//一个GUID例子：m_hEvent = ::CreateEvent(NULL, FALSE, FALSE, TEXT("{67BDE5D7-C2FC-49f5-9096-C255AB791B75}"));
		swprintf_s(EventName, ARRAYSIZE(EventName), L"_Event_0x%X_0x%X", ThreadID, GetTickCount());

		BeginCall64();

		PushUInt64(NULL);	// lpEventAttributes
		PushUInt64(TRUE);	// bManualReset
		PushUInt64(FALSE);	// bInitialState
		PushUnicodeString(EventName); // lpName
		PushCall(CALLING_CONVENTION_WIN64, (FARPROC)CreateEventW);

		//Save event handle
#ifdef _WIN64
		//mov  rdx, [rsp + 8]
		AddByteToBuffer(0x48);
		AddByteToBuffer(0x8B);
		AddByteToBuffer(0x54);
		AddByteToBuffer(0x24);
		AddByteToBuffer(sizeof(size_t));
#else
		AddByteToBuffer(0x48);
		AddByteToBuffer(0x8B);
		AddByteToBuffer(0x54);
		AddByteToBuffer(0x24);
		AddByteToBuffer(sizeof(size_t));
#endif   

        //mov  [rdx+0x8], rax
		AddByteToBuffer(0x48);
		AddByteToBuffer(0x89);
		AddByteToBuffer(0x42);
		AddByteToBuffer(sizeof(size_t));
		ExitThreadWithStatus();

		EndCall64();

		unsigned char *v1 = new unsigned char[m_LocalShellCodeVector.size()];

		for (int i = 0; i < (int)m_LocalShellCodeVector.size(); i++)
		{
			v1[i] = m_LocalShellCodeVector[i];
		}

		/*
		VOID
		NTAPI
		RtlExitUserThread (
			IN NTSTATUS ExitStatus);
		
		*/


			
		//目标进程中申请内存并写入ShellCode
		/*
		0:020> u 0x0000021e02220000 l 50
		0000021e`02220000 48894c2408      mov     qword ptr [rsp+8],rcx
		0000021e`02220005 4889542410      mov     qword ptr [rsp+10h],rdx
		0000021e`0222000a 4c89442418      mov     qword ptr [rsp+18h],r8
		0000021e`0222000f 4c894c2420      mov     qword ptr [rsp+20h],r9
		0000021e`02220014 4883ec38        sub     rsp,38h
		0000021e`02220018 48b90000000000000000 mov rcx,0
		0000021e`02220022 48ba0100000000000000 mov rdx,1
		0000021e`0222002c 49b80000000000000000 mov r8,0
		0000021e`02220036 49b9000021021e020000 mov r9,21E02210000h
		0000021e`02220040 49bd90237629fb7f0000 mov r13,offset KERNEL32!CreateEventW (00007ffb`29762390)
		0000021e`0222004a 41ffd5          call    r13
		0000021e`0222004d 4883c438        add     rsp,38h
		0000021e`02220051 488b542408      mov     rdx,qword ptr [rsp+8]
		0000021e`02220056 48894208        mov     qword ptr [rdx+8],rax
		0000021e`0222005a 4889c1          mov     rcx,rax
		0000021e`0222005d 49bdc0771d2afb7f0000 mov r13,offset ntdll!RtlExitUserThread (00007ffb`2a1d77c0)
		0000021e`02220067 41ffd5          call    r13
		0000021e`0222006a 488b4c2408      mov     rcx,qword ptr [rsp+8]
		0000021e`0222006f 488b542410      mov     rdx,qword ptr [rsp+10h]
		0000021e`02220074 4c8b442418      mov     r8,qword ptr [rsp+18h]
		0000021e`02220079 4c8b4c2420      mov     r9,qword ptr [rsp+20h]
		0000021e`0222007e c3              ret

		
		*/

		//目标进程中的ShellCode
		v2 = CommitProcessMemory(m_ProcessHandle,v1, m_LocalShellCodeVector.size());

		delete[] v1;

		if (v2 == NULL)
		{
			
			OnFreeMember();
			return NULL;
		}

		HANDLE ThreadHandle = NtCreateThreadEx(m_ProcessHandle, (LPTHREAD_START_ROUTINE)v2, m_RemoteWorkerCode, NULL);
		if (ThreadHandle)
		{
			WaitForSingleObject(ThreadHandle, INFINITE);

			if (GetExitCodeThread(ThreadHandle, (LPDWORD)&Status) == 0)
			{
			}

		}

		//因为是一个命名事件所以在当前进程中是可以访问该事件
		m_WaitEventHandle = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, EventName);


	
		if (v2)
		{
			//销毁目标进程中的内存
			FreeProcessMemory(m_ProcessHandle,v2, m_LocalShellCodeVector.size());
		}
		
		OnFreeMember();

		if (Status == NULL || m_WaitEventHandle == NULL)
		{
			SetLastError(ERROR_OBJECT_NOT_FOUND);
			return FALSE;
		}
	}

	return TRUE;
}
void CRemoter::ExitThreadWithStatus()
{

	/*
	VOID ExitThread(  DWORD dwExitCode   // exit code for this thread);
	
	*/


	//mov  rcx, rax
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x89);
	AddByteToBuffer(0xC1);
	//mov  r13, [ExitThread]
	AddByteToBuffer(0x49);
	AddByteToBuffer(0xBD);
	AddLong64ToBuffer((INT_PTR)ExitThread);
	//call r13
	AddByteToBuffer(0x41);
	AddByteToBuffer(0xFF);
	AddByteToBuffer(0xD5);
}






BOOL CRemoter::FixProcessImportTable(PVOID BaseAddress, PVOID RemoteBaseAddress)
{

	PIMAGE_NT_HEADERS ImageNtHeaders = ImageNtHeadersEx(BaseAddress);
	if (ImageNtHeaders == NULL)
	{
		return FALSE;
	}
	if (ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		//内存粒度转换文件粒度
		PIMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor =
			(PIMAGE_IMPORT_DESCRIPTOR)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, BaseAddress);
		if (ImageImportDescriptor)
		{
			for (; ImageImportDescriptor->Name; ImageImportDescriptor++)
			{
			
				char* ModuleName = (char*)RvaToPointer(ImageImportDescriptor->Name, BaseAddress);
				if (ModuleName == NULL)
				{
					continue;
				}

				
				//通过模块名称在目标进程空间中获得模块地址
				HMODULE ModuleBase = GetProcessModuleHandleA(m_ProcessHandle, ModuleName);
				if (ModuleBase == NULL)
				{
					//根据模块的名称获得模块的完整路径
					std::string v1 = ModuleName;
					std::wstring ModuleFullPath = L"";

					ModuleFullPath.assign(v1.begin(), v1.end());
					ResolvePath(ModuleFullPath, RESOLVE_FLAG_ENSURE_FULL_PATH);
					//目标进程加载

					if (m_Is64Bit)
					{

						//没有实现该情况
						//ModuleBase = LoadLibraryByPathIntoMemoryW(ModuleFullPath.c_str(), TRUE);
					
						ModuleBase = LoadLibraryByPathW(ModuleFullPath.c_str());
					}
					else
					{

						ModuleBase = LoadLibraryByPathW(ModuleFullPath.c_str());
					}
						
					if (ModuleBase == NULL)
					{
						continue;
					}

				}

				IMAGE_THUNK_DATA *OriginalFirstThunk = NULL;
				IMAGE_THUNK_DATA *FirstThunk = NULL;

				if (ImageImportDescriptor->OriginalFirstThunk)
				{
					OriginalFirstThunk = (IMAGE_THUNK_DATA*)RvaToPointer(ImageImportDescriptor->OriginalFirstThunk, BaseAddress);
					FirstThunk = (IMAGE_THUNK_DATA*)RvaToPointer(ImageImportDescriptor->FirstThunk, BaseAddress);
				}
				else
				{
					OriginalFirstThunk = (IMAGE_THUNK_DATA*)RvaToPointer(ImageImportDescriptor->FirstThunk, BaseAddress);
					FirstThunk = (IMAGE_THUNK_DATA*)RvaToPointer(ImageImportDescriptor->FirstThunk, BaseAddress);
				}

				if (OriginalFirstThunk == NULL)
				{
					//不用处理
				}
				if (FirstThunk == NULL)
				{
					//不用处理
				}

				for (; OriginalFirstThunk->u1.AddressOfData; OriginalFirstThunk++, FirstThunk++)
				{
					FARPROC FunctionAddress = NULL;

					BOOL v1 = m_Is64Bit ? ((OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0) :
						((OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) != 0);
					//索引导入Ordinal
					if (v1)
					{
						SHORT Ordinal = (SHORT)(OriginalFirstThunk->u1.Ordinal & 0xffff);

						//根据索引在目标进程的ModuleBase中获取函数地址
						FunctionAddress = (FARPROC)GetProcessProcAddressA(ModuleBase, (const char*)Ordinal);

						//获取失败
						if (FunctionAddress == 0)
						{
							return FALSE;
						}
					}
					//名称导入
					else
					{
						PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToPointer(*(DWORD*)OriginalFirstThunk, BaseAddress);
						char* v2 = (char*)ImageImportByName->Name;
						FunctionAddress = (FARPROC)GetProcessProcAddressA(ModuleBase, v2);
					}

					//修正导入表
					FirstThunk->u1.Function = (size_t)FunctionAddress;
				}
			}
			return TRUE;
		}
		else
		{

			return FALSE;
		}
	}
	else
	{
		return TRUE;
	}

	return FALSE;
}
BOOL CRemoter::FixProcessDelayedImportTable(PVOID BaseAddress, PVOID RemoteBaseAddress)
{
	PIMAGE_NT_HEADERS ImageNtHeaders = ImageNtHeadersEx(BaseAddress);;
	if (ImageNtHeaders == NULL)
	{
		return FALSE;
	}
	if (ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size)
	{
		//延迟导入表存在
		PIMAGE_IMPORT_DESCRIPTOR ImageDelayedImportDescriptor = 
			(PIMAGE_IMPORT_DESCRIPTOR)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress,
				BaseAddress);

		if (ImageDelayedImportDescriptor)
		{
			for (; ImageDelayedImportDescriptor->Name; ImageDelayedImportDescriptor++)
			{
				PCHAR ModuleName = (PCHAR)RvaToPointer(ImageDelayedImportDescriptor->Name, BaseAddress);
				if (ModuleName == NULL)
				{
				    //没有延迟导入模块
					continue;
				}

				//在目标进程空间中获取延迟导入模块
				HMODULE ModuleBase = GetProcessModuleHandleA(m_ProcessHandle,ModuleName);
				if (ModuleBase == NULL)
				{
					std::string v1 = ModuleName;
					std::wstring ModuleFullPath = L"";

					ModuleFullPath.assign(v1.begin(), v1.end());
					
					//根据模块的名称获取模块的完整路径
					ResolvePath(ModuleFullPath, RESOLVE_FLAG_ENSURE_FULL_PATH);
					

					if (m_Is64Bit)
					{
						ModuleBase = LoadLibraryByPathW(ModuleFullPath.c_str());
					}
					else
					{
						ModuleBase = LoadLibraryByPathW(ModuleFullPath.c_str());
					}	
					if (ModuleBase == NULL)
					{
						continue;
					}
				}

				IMAGE_THUNK_DATA *OriginalFirstThunk = NULL;
				IMAGE_THUNK_DATA *FirstThunk = NULL;


				if (ImageDelayedImportDescriptor->OriginalFirstThunk)
				{
			
					OriginalFirstThunk = (IMAGE_THUNK_DATA*)RvaToPointer(ImageDelayedImportDescriptor->OriginalFirstThunk, BaseAddress);
					FirstThunk = (IMAGE_THUNK_DATA*)RvaToPointer(ImageDelayedImportDescriptor->FirstThunk, BaseAddress);
				}
				else
				{
	
					OriginalFirstThunk = (IMAGE_THUNK_DATA*)RvaToPointer(ImageDelayedImportDescriptor->FirstThunk, BaseAddress);
					FirstThunk = (IMAGE_THUNK_DATA*)RvaToPointer(ImageDelayedImportDescriptor->FirstThunk, BaseAddress);
				}
				if (OriginalFirstThunk == NULL)
				{
				}

				if (FirstThunk == NULL)
				{
				}

				for (; OriginalFirstThunk->u1.AddressOfData; OriginalFirstThunk++, FirstThunk++)
				{
					FARPROC FunctionAddress = NULL;

					BOOL v1 = FALSE;
									
					if (m_Is64Bit)
					{
						v1 = ((OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0);
					}
						
					else
					{
						v1 = ((OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) != 0);
					}					

					if (v1)
					{
						SHORT Ordinal = (SHORT)(OriginalFirstThunk->u1.Ordinal & 0xffff);

						//根据函数索引目标进程中获得函数地址
						FunctionAddress = (FARPROC)GetProcessProcAddressA(ModuleBase, (const char*)Ordinal); 

						if (FunctionAddress == 0)
						{
				
							return FALSE;
						}
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToPointer(*(DWORD*)OriginalFirstThunk, BaseAddress);

						//根据函数名称目标进程中获得函数地址
						FunctionAddress = (FARPROC)GetProcessProcAddressA(ModuleBase, (LPCCH)ImageImportByName->Name);
						
						if (FunctionAddress == 0)
						{
							
							return FALSE;
						}
					}

					//修正延迟导入表
					FirstThunk->u1.Function = (ULONGLONG)FunctionAddress;
				}
			}

			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		return TRUE;
	}

	return FALSE;
}
BOOL CRemoter::FixProcessBaseRelocationTable(PVOID BaseAddress, PVOID RemoteBaseAddress)
{
	IMAGE_NT_HEADERS* ImageNtHeaders = ImageNtHeadersEx(BaseAddress);
	if (ImageNtHeaders == NULL)
	{
		return FALSE;
	}
	if (ImageNtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
	{
		//重定向表被剥夺
		return TRUE;
	}
	else
	{
		//获取重定向差值
		//实际加载地址-可选头预设ImageBase就是差值
		size_t Delta = CalcDelta(size_t, RemoteBaseAddress, ImageNtHeaders->OptionalHeader.ImageBase);

		DWORD v1 = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;


		//如果存在重定向表
		if (v1)
		{
			PIMAGE_BASE_RELOCATION ImageBaseRelocation = 
				(PIMAGE_BASE_RELOCATION)RvaToPointer(
					ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, BaseAddress);
			if (ImageBaseRelocation)
			{


				PVOID v2 = reinterpret_cast<PBYTE>(ImageBaseRelocation) + v1;

				while (ImageBaseRelocation < v2)
				{
					
					PBYTE v3 = static_cast<PBYTE>(RvaToPointer(ImageBaseRelocation->VirtualAddress, BaseAddress));

					//计算以一个重定位表的WORD重定向个数
					DWORD ItemCount = (ImageBaseRelocation->SizeOfBlock - 8) >> 1;

					//重定向的项数组地址
					PWORD ImageRelocationItem = reinterpret_cast<PWORD>(ImageBaseRelocation + 1);


					for (DWORD i = 0; i < ItemCount; ++i, ++ImageRelocationItem)
					{
						if (FixProcessBaseRelocationItem(Delta, *ImageRelocationItem, v3) == FALSE)
						{
						}
					}

					ImageBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(ImageRelocationItem);
				}
			}
			else
			{
				return FALSE;
			}
		}
		else
		{
			return TRUE;
		}
	}

	return TRUE;
}
BOOL CRemoter::FixProcessBaseRelocationItem(size_t Delta, WORD ImageRelocationItem, PBYTE VirtualAddress)
{
	BOOL IsOk = TRUE;
	//高4位是重定向类型，低12位是重定向地址数据偏移
	//根据重定向类型修复地址
	switch (IMR_RELTYPE(ImageRelocationItem))
	{
	case IMAGE_REL_BASED_HIGH:
	{
		SHORT* v1 = (SHORT*)(VirtualAddress + IMR_RELOFFSET(ImageRelocationItem));

		*v1 += (ULONG)HIWORD(Delta);
		break;
	}
	case IMAGE_REL_BASED_LOW:
	{
		SHORT* v1 = (SHORT*)(VirtualAddress + IMR_RELOFFSET(ImageRelocationItem));


		*v1 += (ULONG)LOWORD(Delta);

		break;
	}
	case IMAGE_REL_BASED_HIGHLOW:
	{
		size_t* v1 = (size_t*)(VirtualAddress + IMR_RELOFFSET(ImageRelocationItem));

		*v1 += (size_t)Delta;

		break;
	}
	case IMAGE_REL_BASED_DIR64:
	{
		DWORD_PTR UNALIGNED* v1 = (DWORD_PTR UNALIGNED*)(VirtualAddress + IMR_RELOFFSET(ImageRelocationItem));

		*v1 += Delta;

		break;
	}
	case IMAGE_REL_BASED_ABSOLUTE: //No action required
	{
		break;
	}
	case IMAGE_REL_BASED_HIGHADJ:  //No action required
	{
		break;
	}
	default:
	{

		IsOk = FALSE;

		break;
	}
	}
	return IsOk;
}
BOOL CRemoter::FixProcessSections(PVOID BaseAddress, PVOID RemoteBaseAddress, BOOL IsPEHeader)
{
	PIMAGE_NT_HEADERS ImageNtHeaders = ImageNtHeadersEx(BaseAddress);
	if (ImageNtHeaders == NULL)
	{
		return FALSE;
	}
	//向目标进程空间中写入模块头部信息
	if (IsPEHeader)
	{
		//头部不需要对齐直接写入
		if (WriteProcessMemory(m_ProcessHandle, RemoteBaseAddress, BaseAddress, ImageNtHeaders->OptionalHeader.SizeOfHeaders, NULL) == FALSE)
		{
			//不用处理
		}
		else
		{
			//不用处理
		}
	}
	else
	{
	}
	PIMAGE_SECTION_HEADER ImageSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);
	for (DWORD i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (_stricmp(".reloc", (char*)ImageSectionHeader[i].Name) == 0)
		{

			//重定向节不用处理
			continue; 
		}

		//Skip discardable sections
		if (ImageSectionHeader[i].Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE))
		{
			//从文件粒度读取获取节属性信息
			ULONG Protection = GetSectionProtection(ImageSectionHeader[i].Characteristics);

			//设置属性信息到目标进程中的内存粒度对齐的内存中
			if (FixProcessSection(ImageSectionHeader[i].Name, BaseAddress, RemoteBaseAddress, 
				ImageSectionHeader[i].PointerToRawData, 
				ImageSectionHeader[i].VirtualAddress, 
				ImageSectionHeader[i].SizeOfRawData, 
				ImageSectionHeader[i].Misc.VirtualSize, 
				Protection) == FALSE)
			{
				//不用处理
			}
			else
			{
				//不用处理
			}
		}
	}

	return TRUE;
}
BOOL CRemoter::FixProcessSection(BYTE* SectionName, PVOID BaseAddress, PVOID RemoteBaseAddress, ULONGLONG PointerToRawData,
	ULONGLONG VirtualAddress, ULONGLONG SizeOfRawData, ULONGLONG VirtualSize, ULONG Protection)
{
	if (WriteProcessMemory(m_ProcessHandle, MakePtr(PVOID, RemoteBaseAddress, VirtualAddress), MakePtr(PVOID, BaseAddress, PointerToRawData), 
		(SIZE_T)SizeOfRawData, NULL) == FALSE)
	{
		return FALSE;
	}

	DWORD OldProtect = NULL;
	if (VirtualProtectEx(m_ProcessHandle, MakePtr(PVOID, RemoteBaseAddress, VirtualAddress), (SIZE_T)VirtualSize, Protection, &OldProtect) == FALSE)
	{
		return FALSE;
	}

	return TRUE;
}
BOOL CRemoter::ExecuteProcessTLSCallBack(PVOID BaseAddress, PVOID RemoteBaseAddress)
{
	IMAGE_NT_HEADERS* ImageNtHeaders = ImageNtHeadersEx(BaseAddress);
	if (ImageNtHeaders == NULL)
		return FALSE;
	if (ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0)
	{

		return TRUE;
	}

	PIMAGE_TLS_DIRECTORY ImageTlsDirectory = (PIMAGE_TLS_DIRECTORY)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,
		BaseAddress);
	if (ImageTlsDirectory == NULL)
	{
		return TRUE;
	}
	if (ImageTlsDirectory->AddressOfCallBacks == NULL)
	{
		return TRUE; 
	}
	

	//定义函数指针
	PIMAGE_TLS_CALLBACK v1[0xFF] = { 0 };

	//Dll中存在TLS
	if (ReadProcessMemory(m_ProcessHandle, (void*)ImageTlsDirectory->AddressOfCallBacks, v1, sizeof(v1), NULL) == FALSE)
	{
		return FALSE;
	}

	//执行TLSCallBack
	BOOL IsOk = TRUE;
	for (int i = 0; v1[i]; i++)
	{
		//ShellCode构建执行目标进程家的TLS回调函数指针表
		if (CallEntryPoint(RemoteBaseAddress, (FARPROC)v1[i]) == FALSE)
		{

		}
		else
		{
			//不用处理
		}
	}

	return IsOk;
}

BOOL CRemoter::CallEntryPoint(void* BaseAddress, FARPROC EntryPoint)
{

	if (m_Is64Bit)
	{
		/* Call the actual entry point */
		BeginCall64();
		PushInt64((unsigned __int64)BaseAddress);
		PushInt64(DLL_PROCESS_ATTACH);
		PushInt64(0x00);
		PushCall(CALLING_CONVENTION_WIN64, EntryPoint);

		//Signal wait event
		SaveReturnValueAndSignalEvent();
		//Restore registers from stack and return
		EndCall64();

		size_t IsOk;
		if (ExecuteInWorkerThread(m_LocalShellCodeVector, IsOk) != ERROR_SUCCESS)
		{
			TerminateWorkerThread();  //销毁我们申请的线程
			OnFreeMember();
			return FALSE;
		}

		return TRUE;

	}
	//push ebp
	//mov  ebp,esp
	AddByteToBuffer(0x55);
	AddByteToBuffer(0x8B);
	AddByteToBuffer(0xEC);

	// x86 injection
	PushInt((INT)BaseAddress);
	PushInt(DLL_PROCESS_ATTACH);
	PushInt(0);
	PushCall(CALLING_CONVENTION_STDCALL, EntryPoint);
	//Zero eax and return
	//xor eax, eax
	AddByteToBuffer(0x33);
	AddByteToBuffer(0xC0);

	//mov esp,ebp
	AddByteToBuffer(0x8B);
	AddByteToBuffer(0xE5);

	//pop ebp
	AddByteToBuffer(0x5D);

	// ret 4
	AddByteToBuffer(0xC2);
	AddByteToBuffer(0x04);
	AddByteToBuffer(0x00);

	return ExecuteProcessMemoryData(m_ProcessHandle,m_LocalShellCodeVector, TRUE);
}
DWORD CRemoter::ExecuteInWorkerThread(SHELL_CODE ShellCodeVector, size_t&ReturnValue)
{
	DWORD Status = ERROR_SUCCESS;
	void* v1 = NULL;

	unsigned char *v2 = new unsigned char[ShellCodeVector.size()];

	for (int i = 0; i < (int)ShellCodeVector.size(); i++)
	{
		v2[i] = ShellCodeVector[i];
	}
	//Write code
	v1 = CommitProcessMemory(m_ProcessHandle,v2, ShellCodeVector.size());

	delete[] v2;

	if (v1 == NULL)
	{
		return FALSE;
	}

	//Create thread if needed
	if (!m_WorkerThreadHandle)
	{
		CreateProcessProcedureCallEnvironment();
	}
	
	//Reset wait event
	if (m_WaitEventHandle)
	{
		//设置为不授信
		ResetEvent(m_WaitEventHandle);

	}	
	/*
	00000202`95640000 4883ec38        sub     rsp,38h
	00000202`95640004 48b90000619502020000 mov rcx,20295610000h     //hModule
	00000202`9564000e 48ba0100000000000000 mov rdx,1                //ul_reason_for_call
	00000202`95640018 49b80000000000000000 mov r8,0                 //lpReserved
	00000202`95640022 49bda312629502020000 mov r13,202956212A3h     //DllMain
	00000202`9564002c 41ffd5          call    r13
	00000202`9564002f 4883c438        add     rsp,38h
	00000202`95640033 488b542408      mov     rdx,qword ptr [rsp+8]     m_RemoteWorkerCode     事件句柄
	00000202`95640038 488902          mov     qword ptr [rdx],rax
	00000202`9564003b 488b4a08        mov     rcx,qword ptr [rdx+8]     m_WaitEventHandle
	00000202`9564003f 49bdb0247629fb7f0000 mov r13,offset KERNEL32!SetEvent (00007ffb`297624b0)
	00000202`95640049 41ffd5          call    r13
	00000202`9564004c 488b4c2408      mov     rcx,qword ptr [rsp+8]
	00000202`95640051 488b542410      mov     rdx,qword ptr [rsp+10h]
	00000202`95640056 4c8b442418      mov     r8,qword ptr [rsp+18h]
	00000202`9564005b 4c8b4c2420      mov     r9,qword ptr [rsp+20h]
	00000202`95640060 c3              ret
	*/

	//Execute code in thread context
	if (QueueUserAPC((PAPCFUNC)v1, m_WorkerThreadHandle, (ULONG_PTR)m_RemoteWorkerCode))
	{
		Status = WaitForSingleObject(m_WaitEventHandle, INFINITE);



		//卸载动态库
		ReadProcessMemory(m_ProcessHandle, m_RemoteWorkerCode, &ReturnValue, sizeof(size_t), NULL);
	}
	Sleep(5);

	
    FreeProcessMemory(m_ProcessHandle,v1, ShellCodeVector.size());


	OnFreeMember();

	return Status;
}

DWORD CRemoter::TerminateWorkerThread()
{
	if (m_WaitEventHandle)
	{
		CloseHandle(m_WaitEventHandle);
		m_WaitEventHandle = NULL;
	}

	if (m_WorkerThreadHandle)
	{
		BOOL IsOk = TerminateThread(m_WorkerThreadHandle, 0);
		m_WorkerThreadHandle = NULL;

		if (m_RemoteWorkerCode)
		{
			FreeProcessMemory(m_ProcessHandle,m_RemoteWorkerCode, 0x1000);
			m_RemoteWorkerCode = NULL;
		}

		return IsOk == TRUE;
	}
	else
		return ERROR_SUCCESS;
}
void CRemoter::SaveReturnValueAndSignalEvent()
{
	
	// mov rdx, [rsp + 0x8]
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x8B);
	AddByteToBuffer(0x54);
	AddByteToBuffer(0x24);
	AddByteToBuffer(0x08);
	// mov [rdx], rax
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x89);
	AddByteToBuffer(0x02);

	// SetEvent(hEvent)
	// mov rcx, [rdx + 0x8]
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x8B);
	AddByteToBuffer(0x4A);
	AddByteToBuffer(0x08);
	// mov r13, SetEvent
	AddByteToBuffer(0x49);
	AddByteToBuffer(0xBD);
	AddLong64ToBuffer((INT_PTR)SetEvent);
	// call r13
	AddByteToBuffer(0x41);
	AddByteToBuffer(0xFF);
	AddByteToBuffer(0xD5);
}
BOOL CRemoter::InitializeCookie(PVOID BaseAddress, PVOID RemoteBaseAddress)
{
	PIMAGE_NT_HEADERS ImageNtHeaders = ImageNtHeadersEx(BaseAddress);
	if (ImageNtHeaders == NULL)
	{
		return FALSE;
	}
	PIMAGE_LOAD_CONFIG_DIRECTORY ImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, BaseAddress);


	if (ImageLoadConfigDirectory && ImageLoadConfigDirectory->SecurityCookie)
	{
		FILETIME v1 = { 0 };
		LARGE_INTEGER v2 = { { 0 } };
		uintptr_t Cookie = 0;

		GetSystemTimeAsFileTime(&v1);
		QueryPerformanceCounter(&v2);

		Cookie = (DWORD)m_ProcessID ^ (DWORD)GetCurrentProcessId() ^ reinterpret_cast<uintptr_t>(&Cookie);

#ifdef _M_AMD64
	
#else

		Cookie ^= v1.dwHighDateTime ^ v1.dwLowDateTime;
		Cookie ^= v2.LowPart;
		Cookie ^= v2.HighPart;

		if (Cookie == 0xBB40E64E)
			Cookie++;
		else if (!(Cookie & 0xFFFF0000))
			Cookie |= (Cookie | 0x4711) << 16;
#endif

		size_t v3 = (size_t)ImageLoadConfigDirectory->SecurityCookie - (size_t)BaseAddress + (size_t)RemoteBaseAddress;

		if (!WriteProcessMemory(m_ProcessHandle, (void*)v3, (const void*)Cookie, sizeof(uintptr_t), NULL))
		{

			return FALSE;
		}

		return TRUE;
	}

	return TRUE;
}
DWORD CRemoter::ResolvePath(std::wstring& FileFullPath, RESOLVE_FLAG ResolveFlag, const std::wstring& BaseName)
{

	std::wstring v1;
	wchar_t v2[4096] = { 0 };
	//小写转换
	std::transform(FileFullPath.begin(), FileFullPath.end(), FileFullPath.begin(), ::tolower);

	//获取文件名称
	//例如，将 C : \test\abc.dll 提取为 abc.dll
	std::wstring FileName = StripPath(FileFullPath);


	//'ext-ms-' are resolved the same way 'api-ms-' are
	//若文件名以 ext-ms- 开头（类似 api-ms-，是 Windows 系统 API 的特殊命名格式，用于组件化管理），
	//则删除前 4 个字符（转为 ms-xxx 格式），统一后续解析逻辑（与 api-ms- 处理方式对齐）。
	if (FileName.find(L"ext-ms-") == 0)
	{
		FileName.erase(0, 4);
	}

	//
	//ApiSchema redirection
	//
	auto i = m_ApiSchemaMap.find(FileName);
	//如果在模板中存在
	if (i != m_ApiSchemaMap.end())
	{
		// Select appropriate api host
		FileFullPath = i->second.front() != BaseName ? i->second.front() : i->second.back();

		//ProbeSxSRedirect 检查是否存在 SxS 重定向（Windows 并行组件机制，用于管理不同版本的组件，解决DLL地狱问题，同名但不同版本的DLL）
		//调用若成功则直接返回解析后的路径。
		if (ProbeSxSRedirect(FileFullPath) == STATUS_SUCCESS)
			return STATUS_SUCCESS;
		else if (ResolveFlag & RESOLVE_FLAG_ENSURE_FULL_PATH)
		{
			wchar_t v1[255] = { 0 };
			GetSystemDirectoryW(v1, 255);
			FileFullPath = std::wstring(v1) + L"\\" + FileFullPath;
		}

		return STATUS_SUCCESS;
	}




	if (ResolveFlag & RESOLVE_FLAG_API_SCHEMA_ONLY)
	{
		SetLastError(ERROR_NOT_FOUND);
		return ERROR_NOT_FOUND;
	}

	//SxS redirection 没有完成
	if (ProbeSxSRedirect(FileFullPath) == ERROR_SUCCESS)
		return ERROR_SUCCESS;


	//Perform search accordingly to Windows Image loader search order 
	//1. KnownDlls 注册表项：
	HKEY KeyHandle = NULL;
	LRESULT Result = 0;
	Result = RegOpenKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", &KeyHandle);
	if (Result == 0)
	{
		for (int i = 0; i < 0x1000 && Result == ERROR_SUCCESS; i++)
		{
			wchar_t v1[255] = { 0 };
			wchar_t v2[255] = { 0 };

			DWORD ReturnLength = 255;
			DWORD KeyType = 0;

			Result = RegEnumValueW(KeyHandle, i, v1, &ReturnLength, NULL, &KeyType, (LPBYTE)v2, &ReturnLength);

			if (_wcsicmp(v2, FileName.c_str()) == 0)
			{
				wchar_t v3[255] = { 0 };
				ReturnLength = 255;

				// In Win10 DllDirectory value got screwed, so less reliable method is used
				GetSystemDirectoryW(v3, ReturnLength);

				if (Result == ERROR_SUCCESS)
				{
					FileFullPath = std::wstring(v3) + L"\\" + v2;

					RegCloseKey(KeyHandle);
					return ERROR_SUCCESS;
				}
			}
		}

		RegCloseKey(KeyHandle);
	}

	//
	//2. 应用程序加载目录：
	//
	v1 = GetProcessDirectory(m_ProcessHandle) + L"\\" + FileName;
	
	//判断文件是否存在
	if (FileExists(v1))
	{
		FileFullPath = v1;
		return ERROR_SUCCESS;
	}

	//
	// 3. 系统目录（System32）：
	//
	GetSystemDirectoryW(v2, ARRAYSIZE(v2));
	v1 = std::wstring(v2) + L"\\" + FileName;
	if (FileExists(v1))
	{
		FileFullPath = v1;
		return ERROR_SUCCESS;
	}

	//
	// 4. The Windows directory
	//
	GetWindowsDirectoryW(v2, ARRAYSIZE(v2));
	v1 = std::wstring(v2) + L"\\" + FileName;
	if (FileExists(v1))
	{
		FileFullPath = v1;
		return ERROR_SUCCESS;
	}

	//
	// 5. The current directory
	//
	GetCurrentDirectoryW(ARRAYSIZE(v2), v2);


	v1 = std::wstring(v2) + L"\\" + FileName;
	if (FileExists(v1))
	{
		FileFullPath = v1;
		return ERROR_SUCCESS;
	}

	GetEnvironmentVariableW(L"PATH", v2, ARRAYSIZE(v2));
	wchar_t *v3;

	for (wchar_t *v4 = wcstok_s(v2, L";", &v3); v4; v4 = wcstok_s(v3, L";", &v3))
	{
		v1 = std::wstring(v4) + L"\\" + FileName;
		if (FileExists(v1))
		{
			FileFullPath = v1;
			return ERROR_SUCCESS;
		}
	}

	SetLastError(ERROR_NOT_FOUND);
	return ERROR_NOT_FOUND;
}
DWORD CRemoter::ProbeSxSRedirect(std::wstring& FileFullPath)
{
	UNICODE_STRING v1;
	ZeroMemory(&v1, sizeof(UNICODE_STRING));
	UNICODE_STRING v2;
	ZeroMemory(&v2, sizeof(UNICODE_STRING));
	UNICODE_STRING v3;
	ZeroMemory(&v3, sizeof(UNICODE_STRING));
	PUNICODE_STRING v4 = NULL;
	ULONG_PTR cookie = 0;
	wchar_t v5[255] = { 0 };


	static HMODULE NtdllModuleBase = GetModuleHandle01("ntdll.dll");
	static LPFN_RTLINITUNICODESTRING  _RtlInitUnicodeString = (LPFN_RTLINITUNICODESTRING)GetProcAddress01(NtdllModuleBase, "RtlInitUnicodeString");
	static LPFN_RTLFREEUNICODESTRING  _RtlFreeUnicodeString = (LPFN_RTLFREEUNICODESTRING)GetProcAddress01(NtdllModuleBase, "RtlFreeUnicodeString");
	static LPFN_RTLNTSTATUSTODOSERROR _RtlNtStatusToDosError = (LPFN_RTLNTSTATUSTODOSERROR)GetProcAddress01(NtdllModuleBase, "RtlNtStatusToDosError");
	static LPFN_RTLDOSAPPLYFILEISOLATIONREDIRECTION_USTR _RtlDosApplyFileIsolationRedirection_Ustr = 
		(LPFN_RTLDOSAPPLYFILEISOLATIONREDIRECTION_USTR)GetProcAddress01(NtdllModuleBase, "RtlDosApplyFileIsolationRedirection_Ustr");

	_RtlInitUnicodeString(&v1, FileFullPath.c_str());

	v2.Buffer = v5;
	v2.Length = NULL;
	v2.MaximumLength = ARRAYSIZE(v5);

	//Use activation context
	//if (m_hActx && m_hActx != INVALID_HANDLE_VALUE)
	//	ActivateActCtx(m_hActx, &cookie);

	// SxS resolve
	NTSTATUS Status = _RtlDosApplyFileIsolationRedirection_Ustr(TRUE, 
		&v1, NULL, &v2, &v3, &v4, NULL, NULL, NULL);

	//if (cookie != 0 && m_hActx && m_hActx != INVALID_HANDLE_VALUE)
	//	DeactivateActCtx(0, cookie);

	if (Status == STATUS_SUCCESS)
	{
		FileFullPath = v4->Buffer;
	}
	else
	{
		if (v3.Buffer)
		{
			_RtlFreeUnicodeString(&v3);
		}
			

		SetLastError(_RtlNtStatusToDosError(Status));
		return _RtlNtStatusToDosError(Status);
	}

	if (v3.Buffer)
		_RtlFreeUnicodeString(&v3);

	SetLastError(ERROR_SUCCESS);
	return ERROR_SUCCESS;
}

