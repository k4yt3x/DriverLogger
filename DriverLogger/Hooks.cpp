#include "pch.h"

#include <windows.h>
#include <MinHook.h>
#include <stdio.h>
#include <wchar.h>

// Define the path to the log file and the driver name to monitor
const LPCWSTR DRIVER_NAME = L"\\\\.\\\\\\.\\HoYoProtect";
//const LPCWSTR DRIVER_NAME = L"\\\\.\\ACE-BASE";
const LPCWSTR LOG_FILE_PATH = L"C:\\DriverLogger.txt";

// File handle for logging
FILE* hLogFile = nullptr;

// Function pointer typedefs for the original functions
typedef HANDLE(WINAPI* PCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* PReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* PWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* PDeviceIoControl)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

// Pointers to the original functions
PCreateFileW pOriginalCreateFileW = NULL;
PReadFile pOriginalReadFile = NULL;
PWriteFile pOriginalWriteFile = NULL;
PDeviceIoControl pOriginalDeviceIoControl = NULL;

// Handle for the specific device
HANDLE hMonitoredDriver = NULL;

// Function to log both to console and file
void LogMessage(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);

    // Print to the console using wprintf
    vwprintf(format, args);

    // Print to the log file if it is open
    if (hLogFile != nullptr) {
        vfwprintf(hLogFile, format, args);
        fflush(hLogFile); // Ensure data is written immediately
    }

    va_end(args);
}

// Hooked CreateFileW function
HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    HANDLE hFile = pOriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    // Check if the file being opened matches the driver name
    if (wcsstr(lpFileName, DRIVER_NAME) != NULL) {
        hMonitoredDriver = hFile;
        LogMessage(L"[DriverLogger::OPEN] Driver %s opened.\n", lpFileName);
    }

    return hFile;
}

// Hooked ReadFile function
BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    BOOL result = pOriginalReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

    if (hFile == hMonitoredDriver && result && *lpNumberOfBytesRead > 0) {
        LogMessage(L"[DriverLogger::READ] Data from driver: ");
        for (DWORD i = 0; i < *lpNumberOfBytesRead; i++) {
            LogMessage(L"%02X ", ((unsigned char*)lpBuffer)[i]);
        }
        LogMessage(L"\n");
    }

    return result;
}

// Hooked WriteFile function
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    BOOL result = pOriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

    if (hFile == hMonitoredDriver && result && *lpNumberOfBytesWritten > 0) {
        LogMessage(L"[DriverLogger::WRITE] Data to driver: ");
        for (DWORD i = 0; i < *lpNumberOfBytesWritten; i++) {
            LogMessage(L"%02X ", ((unsigned char*)lpBuffer)[i]);
        }
        LogMessage(L"\n");
    }

    return result;
}

BOOL WINAPI HookedDeviceIoControl(
    HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize,
    LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
{
    if (hDevice == hMonitoredDriver) {
        LogMessage(L"[DriverLogger::IOCTL] Control Code: 0x%X\n", dwIoControlCode);

        // Log the input buffer if applicable
        if (nInBufferSize > 0 && lpInBuffer != NULL) {
            LogMessage(L"[DriverLogger::IOCTL] Input Buffer: ");
            for (DWORD i = 0; i < nInBufferSize; i++) {
                LogMessage(L"%02X ", ((unsigned char*)lpInBuffer)[i]);
            }
            LogMessage(L"\n");
        }
    }

    // Call the original DeviceIoControl function
    BOOL result = pOriginalDeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);

    // Log the output buffer after the call to the original function
    if (hDevice == hMonitoredDriver && nOutBufferSize > 0 && lpOutBuffer != NULL) {
        LogMessage(L"[DriverLogger::IOCTL] Output Buffer: ");
        for (DWORD i = 0; i < nOutBufferSize; i++) {
            LogMessage(L"%02X ", ((unsigned char*)lpOutBuffer)[i]);
        }
        LogMessage(L"\n");
    }

    return result;
}

// Initialize hooks
void InitHooks() {
    // Open the log file for writing
    _wfopen_s(&hLogFile, LOG_FILE_PATH, L"w");
    if (hLogFile == nullptr) {
        wprintf(L"[DriverLogger] Failed to open log file at %s\n", LOG_FILE_PATH);
        return;
    }

    // Initialize MinHook
    if (MH_Initialize() != MH_OK) {
        LogMessage(L"[DriverLogger] Failed to initialize MinHook.\n");
        return;
    }

    // Hook CreateFileW
    if (MH_CreateHookApi(L"kernel32", "CreateFileW", &HookedCreateFileW, reinterpret_cast<LPVOID*>(&pOriginalCreateFileW)) != MH_OK) {
        LogMessage(L"[DriverLogger] Failed to hook CreateFileW.\n");
    }

    // Hook ReadFile
    if (MH_CreateHookApi(L"kernel32", "ReadFile", &HookedReadFile, reinterpret_cast<LPVOID*>(&pOriginalReadFile)) != MH_OK) {
        LogMessage(L"[DriverLogger] Failed to hook ReadFile.\n");
    }

    // Hook WriteFile
    if (MH_CreateHookApi(L"kernel32", "WriteFile", &HookedWriteFile, reinterpret_cast<LPVOID*>(&pOriginalWriteFile)) != MH_OK) {
        LogMessage(L"[DriverLogger] Failed to hook WriteFile.\n");
    }

	// Hook DeviceIoControl
    if (MH_CreateHookApi(L"kernel32", "DeviceIoControl", &HookedDeviceIoControl, reinterpret_cast<LPVOID*>(&pOriginalDeviceIoControl)) != MH_OK) {
        LogMessage(L"Failed to hook DeviceIoControl.\n");
    }

    // Enable the hooks
    MH_EnableHook(MH_ALL_HOOKS);

    LogMessage(L"[DriverLogger] Hooks initialized.\n");
}

// Cleanup function for when the DLL is unloaded
void Cleanup() {
    if (hLogFile != nullptr) {
        fclose(hLogFile);
        hLogFile = nullptr;
    }
    MH_Uninitialize();
}
