#include <Windows.h>

#define DUMP_DIRECTORY TEXT("dump")
#define SEARCH_LIMIT 0xB000
#define RANGE_LIMIT 15
const unsigned char SIG[] = {0x80, 0x00, 0xEA, 0x00, 0x48, 0x75, 0xF9};
unsigned int i = 0;

void dummy()
{
	
}

BOOL CompareData(const BYTE* pData, const BYTE* bMask, const char* pszMask)
{
	for(;*pszMask; ++pszMask, ++pData, ++bMask)
		if(*pszMask == 'x' && *pData !=* bMask) 
			return FALSE;
	return (*pszMask) == 0;
}

DWORD FindPattern(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * pszMask)
{
	for(DWORD i=0; i < dwLen; i++)
		if(CompareData((BYTE*)( dwAddress+i ), bMask, pszMask))
			return (DWORD)(dwAddress + i);
	return 0;
}

void Hook()
{
	DWORD pr, addr;
	void * module = GetModuleHandle(NULL);
	if(module != NULL)
	{
		addr = FindPattern(((DWORD)module + 0x1000), SEARCH_LIMIT, (BYTE*)SIG, "x?x?xxx");
		if(addr != 0)
		{
			addr += sizeof(SIG);
			addr = FindPattern(addr, RANGE_LIMIT, (BYTE *)"\xC3", "x");

			VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &pr);
			CopyMemory((void *)addr, "\xCC", 1);
			VirtualProtect((LPVOID)addr, 1, pr, &pr);
		}
	}
}

void Write(char * buf)
{
	DWORD wr;
	wchar_t fname[256];

	wsprintf(fname, L"%ws/%u.txt", DUMP_DIRECTORY, i++);
	HANDLE file = CreateFile(fname, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(file != INVALID_HANDLE_VALUE)
	{
		WriteFile(file, buf, lstrlenA(buf), &wr, NULL);
		CloseHandle(file);
	}
}

LONG CALLBACK VEH(PEXCEPTION_POINTERS ExceptionInfo)
{
	Write((char *)ExceptionInfo->ContextRecord->Eax);

	ExceptionInfo->ContextRecord->Eip = *(DWORD *)ExceptionInfo->ContextRecord->Esp;
	ExceptionInfo->ContextRecord->Esp += sizeof(DWORD);
	
	return EXCEPTION_CONTINUE_EXECUTION;
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	if(dwReason == DLL_PROCESS_ATTACH)
	{
		CreateDirectory(DUMP_DIRECTORY, NULL);
		AddVectoredExceptionHandler(1, VEH);
		Hook();
    }

    return TRUE;
}
