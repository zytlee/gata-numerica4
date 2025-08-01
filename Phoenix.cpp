#undef UNICODE
#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <map>
#include <algorithm>
#include <cctype>
#include <psapi.h>
#include <TlHelp32.h>
#include "starfallPayload.h"
#include "nullrhiPatch.h"
#include <thread>
#include <atomic>

std::vector<std::string> split(const std::string& s, char delim) {
	std::stringstream ss(s);
	std::string item;
	std::vector<std::string> elems;
	while (std::getline(ss, item, delim)) {
		elems.push_back(std::move(item));
	}
	return elems;
}

bool Inject(HANDLE proc, std::string path) {
    auto pathStr = path.c_str();
    auto pathSize = path.size() + 1;
    std::ifstream c(path);
    if (c.fail()) return !printf("Failed to open %s!\n", pathStr);
    c.close();
    void* nameRegion = VirtualAllocEx(proc, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(proc, nameRegion, pathStr, pathSize, NULL);

    HANDLE tr = CreateRemoteThread(proc, 0, 0, (LPTHREAD_START_ROUTINE) LoadLibraryA, nameRegion, 0, 0); // this works because loadlibrarya address is the same in every binary
    WaitForSingleObject(tr, (DWORD)-1);
    CloseHandle(tr);
    VirtualFreeEx(proc, nameRegion, pathSize, MEM_RELEASE);
    return true;
}
HANDLE fnStdoutRd = NULL;
HANDLE fnStdoutWr = NULL;

void killProcessByName(const char* filename)
{
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof(pEntry);
    BOOL hRes = Process32First(hSnapShot, &pEntry);
    while (hRes)
    {
        if (strcmp(pEntry.szExeFile, filename) == 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
                (DWORD)pEntry.th32ProcessID);
            if (hProcess != NULL)
            {
                TerminateProcess(hProcess, 9);
                CloseHandle(hProcess);
            }
        }
        hRes = Process32Next(hSnapShot, &pEntry);
    }
    CloseHandle(hSnapShot);
}

std::map<std::string, std::string> config{};
TCHAR p[MAX_PATH];
bool goEnd = false;
std::atomic<bool> stopWatchdog{false};
std::ofstream logFile;

// Monitors the headless process and restarts the cycle when it exits or crashes
DWORD WatchdogThread(LPVOID pi) {
    PROCESS_INFORMATION processInfo = *(PROCESS_INFORMATION*)pi;
    while (!stopWatchdog.load()) {
        DWORD res = WaitForSingleObject(processInfo.hProcess, 5000);
        if (res == WAIT_OBJECT_0)
            break;
        DWORD code = STILL_ACTIVE;
        if (!GetExitCodeProcess(processInfo.hProcess, &code) || code != STILL_ACTIVE) {
            TerminateProcess(processInfo.hProcess, 0);
            break;
        }
    }
    return 0;
}
DWORD StdoutThread(LPVOID pi) {
    PROCESS_INFORMATION processInfo = *(PROCESS_INFORMATION *) pi;
    char chBuf[4096];
    DWORD dwRead;
    bool check = true;
    while (true) {
        bool bSuccess = ReadFile(fnStdoutRd, chBuf, 4096, &dwRead, NULL);
        if (!bSuccess) break;
        if (dwRead == 0) continue;
        std::string s(chBuf, dwRead);
        logFile.write(s.c_str(), s.size());
        logFile.flush();
        std::cout.write(s.c_str(), s.size());
        std::cout.flush();
        if (check) {
            if (s.contains("CreatingParty")) { // proper !
                std::string gsPath = std::string((char*)p) + "\\Starfall.dll";
                if (!Inject(processInfo.hProcess, gsPath)) {
                    TerminateProcess(processInfo.hProcess, 0);
                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);
                    //goto end;
                    goEnd = true;
                }
                check = false;
            }
            else if (s.contains("[UOnlineAccountCommon::ForceLogout] ForceLogout (")) {
                auto logoutReasonStart = s.find("reason \"") + 8;
                auto logoutReasonEnd = s.substr(logoutReasonStart).find("\"");
                printf("Failed to login: %s\n", s.substr(logoutReasonStart, logoutReasonEnd).c_str());
                TerminateProcess(processInfo.hProcess, 0);

                check = false;
            }
        }
    }
    return 0;   
}

int main()
{
	std::ifstream c("config.txt");
    if (c.fail()) {
        std::ofstream cn("config.txt");
        cn << 
            "# Game path\n"
            "path=\n"
            "# Backend IP in format http(s)://ip:port\n"
            "backend=\n"
            "# Gameserver account email\n"
            "email=\n"
            "# Gameserver account password\n"
            "password=\n"
            "# Restart cooldown in seconds\n"
            "cooldown=10\n"
            "# Launch headless or with client (true/false)\n"
            "headless=true\n";
        cn.close();
        printf("Failed to find config.txt! A blank one for you to configure has been created.\n");
        while (true) {}
    }
	std::string line;
	while (std::getline(c, line)) {
        if (line.starts_with('#')) continue;
        auto s = split(line, '=');
		if (s.size() > 1) config[s[0]] = s[1];
	}
    c.close();
    if (!config.contains("path") || !config.contains("backend") || !config.contains("email") || !config.contains("password")) {
        printf("Config does not have all required values!\n");
        while (true) {}
    }

    DWORD restartCooldownMs = 10000; // default 10 seconds cooldown
    if (config.contains("cooldown")) {
        try {
            int cd = std::stoi(config["cooldown"]);
            if (cd > 0)
                restartCooldownMs = cd * 1000;
        } catch (...) {}
    }

    bool headless = true;
    if (config.contains("headless")) {
        std::string val = config["headless"];
        std::transform(val.begin(), val.end(), val.begin(), [](unsigned char c){ return std::tolower(c); });
        if (val == "false" || val == "0" || val == "no")
            headless = false;
    }

    UINT oldErrMode = SetErrorMode(0);
    SetErrorMode(oldErrMode | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

    auto fn = config["path"];
    std::ifstream f(fn + "\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe");
    if (!f.is_open()) {
        printf("Path is not a valid Fortnite install!\n");
        while (true) {}
    }
    f.close();
    logFile.open("autohost.log", std::ios::app);
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&fnStdoutRd, &fnStdoutWr, &saAttr, 0)) {
        printf("Failed to open stdout pipe!\n");
        while (true) {}
    }
    if (!SetHandleInformation(fnStdoutRd, HANDLE_FLAG_INHERIT, 0)) {
        printf("Failed to open disable inherit on stdout pipe!\n");
        while (true) {}
    }

    TCHAR lpTempPathBuffer[MAX_PATH];

    auto dwRetVal = GetTempPathA(MAX_PATH, lpTempPathBuffer);
    if (dwRetVal > MAX_PATH || (dwRetVal == 0))
    {
        printf("Failed to get temp path!\n");
        while (true) {}
    }

    std::string goofy = std::string(lpTempPathBuffer) + "\\Starfall.dll";
    std::ofstream file(goofy.c_str(), std::ios::binary);
    file.write((const char *) Starfall, sizeof(Starfall));
    file.close();

    std::string nullrhi = std::string(lpTempPathBuffer) + "\\NullrhiPatch.dll";
    std::ofstream nullrhiF(nullrhi.c_str(), std::ios::binary);
    nullrhiF.write((const char*)NullrhiPatch, sizeof(NullrhiPatch));
    nullrhiF.close();

    killProcessByName("FortniteClient-Win64-Shipping.exe");
    killProcessByName("FortniteClient-Win64-Shipping_EAC.exe");
    killProcessByName("FortniteLauncher.exe");

    STARTUPINFOA info = { sizeof(info) };
    ZeroMemory(&info, sizeof(STARTUPINFOA));
    info.cb = sizeof(STARTUPINFOA);
    info.hStdOutput = fnStdoutWr;
    info.dwFlags |= STARTF_USESTDHANDLES;
    STARTUPINFOA Nuh = { sizeof(info) };
    PROCESS_INFORMATION Uh;
    CreateProcessA((fn + "\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping_EAC.exe").c_str(), (char*)"", NULL, NULL, true, CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, fn.c_str(), &Nuh, &Uh);
    STARTUPINFOA Plo = { sizeof(info) };
    PROCESS_INFORMATION Osh;
    CreateProcessA((fn + "\\FortniteGame\\Binaries\\Win64\\FortniteLauncher.exe").c_str(), (char*)"", NULL, NULL, true, CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, fn.c_str(), &Plo, &Osh);
    GetCurrentDirectoryA(MAX_PATH, (LPSTR)p);
    bool firstStart = true;
    while (true) {
        if (firstStart) {
            printf("Starting server...\n");
            firstStart = false;
        }
        else {
            printf("Restarting server...\n");
        }
        std::string params = fn + "\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe -epicapp=Fortnite -epicenv=Prod -epicportal -skippatchcheck -nobe -fromfl=eac -fltoken=3db3ba5dcbd2e16703f3978d -caldera=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50X2lkIjoiYmU5ZGE1YzJmYmVhNDQwN2IyZjQwZWJhYWQ4NTlhZDQiLCJnZW5lcmF0ZWQiOjE2Mzg3MTcyNzgsImNhbGRlcmFHdWlkIjoiMzgxMGI4NjMtMmE2NS00NDU3LTliNTgtNGRhYjNiNDgyYTg2IiwiYWNQcm92aWRlciI6IkVhc3lBbnRpQ2hlYXQiLCJub3RlcyI6IiIsImZhbGxiYWNrIjpmYWxzZX0.VAWQB67RTxhiWOxx7DBjnzDnXyyEnX7OljJm-j2d88G_WgwQ9wrE6lwMEHZHjBd1ISJdUO1UVUqkfLdU5nofBQ";
        if (headless) {
            params += " -nullrhi -nosound -nosplash";
        }
        PROCESS_INFORMATION processInfo;
        CreateProcessA((fn + "\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe").c_str(), (char*)(params + " -AUTH_LOGIN=" + config["email"] + " -AUTH_PASSWORD=" + config["password"] + " -AUTH_TYPE=epic -backend=" + config["backend"]).c_str(), NULL, NULL, true, CREATE_SUSPENDED, nullptr, fn.c_str(), &info, &processInfo);
        if (headless && !Inject(processInfo.hProcess, nullrhi)) {
            TerminateProcess(processInfo.hProcess, 0);
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
            goto end;
        }

        HANDLE tsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        THREADENTRY32 ent;
        ent.dwSize = sizeof(THREADENTRY32);
        Thread32First(tsnap, &ent);

        while (Thread32Next(tsnap, &ent)) {
            if (ent.th32OwnerProcessID == processInfo.dwProcessId) {
                HANDLE thr = OpenThread(THREAD_ALL_ACCESS, FALSE, ent.th32ThreadID);

                ResumeThread(thr);
                CloseHandle(thr);
            }
        }
        CloseHandle(tsnap);

        if (!Inject(processInfo.hProcess, goofy)) {
            TerminateProcess(processInfo.hProcess, 0);
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
            goto end;
        }
        stopWatchdog = false;
        auto t = CreateThread(0, 0, StdoutThread, &processInfo, 0, 0);
        HANDLE w = CreateThread(0, 0, WatchdogThread, &processInfo, 0, 0);
        WaitForSingleObject(processInfo.hProcess, (DWORD)-1);
        stopWatchdog = true;
        WaitForSingleObject(w, (DWORD)-1);
        CloseHandle(w);
        TerminateThread(t, 0);
        CloseHandle(t);
        if (goEnd) goto end;

        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);

        printf("Waiting %u seconds before restart...\n", restartCooldownMs / 1000);
        Sleep(restartCooldownMs);
    }

end:
    TerminateProcess(Uh.hProcess, 0);
    CloseHandle(Uh.hProcess);
    CloseHandle(Uh.hThread);
    TerminateProcess(Osh.hProcess, 0);
    CloseHandle(Osh.hProcess);
    CloseHandle(Osh.hThread);
    if (logFile.is_open()) logFile.close();
}