#include <Windows.h>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

VOID _declspec(dllexport) DirA() {}
BOOL g_fgThreadWait = FALSE;

DWORD g_dwFileSize;
PDWORD g_pFileOffset, g_pFileName, g_pFilePath;
VOID WINAPI DumpFile()
{
	char dumpPath[MAX_PATH] = ".\\Dump\\";
	char packName[MAX_PATH] = { 0 };

	lstrcpyA(packName, (LPCSTR)g_pFilePath);
	PathStripPathA((LPSTR)packName);
	PathAddBackslashA((LPSTR)packName);
	lstrcatA(dumpPath, packName);
	CreateDirectoryA(dumpPath, NULL);

	lstrcatA(dumpPath, (LPCSTR)g_pFileName);

	HANDLE hFile = CreateFileA((LPCSTR)dumpPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		WriteFile(hFile, g_pFileOffset, g_dwFileSize, NULL, NULL);
		FlushFileBuffers(hFile);
		CloseHandle(hFile);
	}

	g_dwFileSize = 0;
	g_pFileOffset = 0;
	g_pFileName = 0;
	g_pFilePath = 0;
}

VOID WINAPI DumpFile(DWORD dwFileSize, PDWORD pFileOffset, PDWORD pFileName, PDWORD pFilePath)
{
	char dumpPath[MAX_PATH] = ".\\Dump\\";
	char packName[MAX_PATH] = { 0 };

	lstrcpyA(packName, (LPCSTR)pFilePath);
	PathStripPathA((LPSTR)packName);
	PathAddBackslashA((LPSTR)packName);
	lstrcatA(dumpPath, packName);
	CreateDirectoryA(dumpPath, NULL);

	lstrcatA(dumpPath, (LPCSTR)pFileName);

	HANDLE hFile = CreateFileA((LPCSTR)dumpPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		WriteFile(hFile, pFileOffset, dwFileSize, NULL, NULL);
		FlushFileBuffers(hFile);
		CloseHandle(hFile);
	}
}

//DWORD g_dwRawAddr = 0x006F7C1B; //Aikiss
DWORD g_dwRawAddr = 0x0073740B; //ParfaitRemake
DWORD g_dwRetAddr = g_dwRawAddr + 0x5;
VOID __declspec(naked) SetFileInfo()
{
	while (g_fgThreadWait)
	{
		Sleep(60);
	}
	g_fgThreadWait = TRUE;

	__asm
	{
		mov ecx, dword ptr ds : [ebx]
		mov eax, dword ptr ds : [esi + 0x20]
		pushad
		pushfd
		mov g_pFileOffset, ecx
		mov g_dwFileSize, eax
		mov eax, [edi]
		mov g_pFilePath, eax
		mov eax, [ebp + 0xC]
		mov ebx, [eax + 0x14]
		cmp ebx, 0x1F
		jne noPoint
		mov eax, [eax]
		noPoint:
		mov g_pFileName, eax
	}

	//DumpFile(g_dwFileSize, g_pFileOffset, g_pFileName, g_pFilePath);
	DumpFile();
	g_fgThreadWait = FALSE;

	__asm
	{
		popfd
		popad
		jmp g_dwRetAddr
	}
}

VOID WriteHookCode(DWORD dwRawAddr, DWORD dwTarAddr)
{
	DWORD oldProtect = 0;
	VirtualProtect((LPVOID)dwRawAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	DWORD rawAddr = dwTarAddr - dwRawAddr - 5;
	BYTE code[] = { 0xE9,0x00,0x00,0x00,0x00 };

	memcpy(&code[1], &rawAddr, 4);
	memcpy((void*)dwRawAddr, code, 5);
}

VOID StartHook()
{
	CreateDirectoryA(".\\Dump\\", NULL);
	WriteHookCode(g_dwRawAddr, (DWORD)SetFileInfo);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		StartHook();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

