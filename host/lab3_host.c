
#include <Windows.h>
#include <stdio.h>

typedef BOOL (*Lab3InitializeFunction)(PCWSTR host, PCWSTR port);
typedef BOOL (*Lab3StartFunction)(VOID);
typedef VOID (*Lab3StopFunction)(VOID);

/**
 * @brief Loads the DLL, resolves the exported runtime entry points, and starts
 *        the polling loop for local testing.
 *
 * The host keeps the DLL loaded until the user presses Enter, then calls the
 * stop export and unloads the library.
 *
 * @return 0 on success, or 1 on failure.
 */
int wmain(int argc, wchar_t* argv[])
{
	HMODULE dllModule = NULL;
	Lab3InitializeFunction lab3Initialize = NULL;
	Lab3StartFunction lab3Start = NULL;
	Lab3StopFunction lab3Stop = NULL;
	PCWSTR dllPath = L"lab3.dll";
	PCWSTR c2Host = L"127.0.0.1";
	PCWSTR c2Port = L"9001";

	if (argc > 1)
	{
		dllPath = argv[1];
	}

	if (argc > 2)
	{
		c2Host = argv[2];
	}

	if (argc > 3)
	{
		c2Port = argv[3];
	}

	wprintf(L"[*] Loading DLL: %ls\n", dllPath);
	dllModule = LoadLibraryW(dllPath);
	if (dllModule == NULL)
	{
		wprintf(L"[!] LoadLibraryW failed: %lu\n", GetLastError());
		return 1;
	}

	lab3Initialize = (Lab3InitializeFunction)GetProcAddress(
		dllModule,
		"Lab3Initialize"
	);
	lab3Start = (Lab3StartFunction)GetProcAddress(dllModule, "Lab3Start");
	lab3Stop = (Lab3StopFunction)GetProcAddress(dllModule, "Lab3Stop");
	if (lab3Initialize == NULL || lab3Start == NULL || lab3Stop == NULL)
	{
		wprintf(L"[!] Failed to resolve one or more exports.\n");
		FreeLibrary(dllModule);
		return 1;
	}

	if (!lab3Initialize(c2Host, c2Port))
	{
		wprintf(L"[!] Lab3Initialize failed.\n");
		FreeLibrary(dllModule);
		return 1;
	}

	if (!lab3Start())
	{
		wprintf(L"[!] Lab3Start failed.\n");
		FreeLibrary(dllModule);
		return 1;
	}

	wprintf(L"[*] Polling started. Press Enter to stop the host.\n");
	(void)getwchar();

	lab3Stop();
	FreeLibrary(dllModule);
	wprintf(L"[*] Host stopped.\n");

	return 0;
}
