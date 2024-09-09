#include "pch.h"

#include <windows.h>
#include <iostream>

#include "Hooks.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		// Allocating a console for debugging purposes
		AllocConsole();

		// Redirecting stdout to the console
		FILE* pFile;
		freopen_s(&pFile, "CONOUT$", "w", stdout);
		wprintf(L"[DriverLogger] Successfully injected into the target process.\n");

		// Initialize hooks
		InitHooks();
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
		// Cleanup and disable all hooks
		Cleanup();
	}
	return TRUE;
}
