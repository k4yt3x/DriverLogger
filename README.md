# DriverLogger

A small library that logs IOCTL and other communications between a program and a driver.

![screenshot](https://github.com/user-attachments/assets/45b2c62e-943a-497a-b596-dd092b0467e4)

The following functions are hooked:

## Usage

Inject the `DriverLogger.dll` into the process you want to monitor with an injector like [Extreme Injector](https://github.com/master131/ExtremeInjector). A console will pop up, displaying all of the intercepted communications. The intercepted data will also be logged to `C:\DriverLogger.txt`. You can customize which driver to monitor and the log file path by compiling the project yourself.

## Build

1. Install Visual Studio and C++ development dependencies.
2. Download and install [vcpkg](https://github.com/microsoft/vcpkg).
3. Install MinHook with `vcpkg install minhook:x64-windows-static`.
4. Build the solution in Visual Studio.
