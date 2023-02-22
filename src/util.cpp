#include "pch.h"
#include "util.h"

#include "resource.h"
#include "b64.h"

namespace util
{
    //const char* FAKEHOST = "https://example.com";

    HMODULE GetSelfModuleHandle()
    {
        MEMORY_BASIC_INFORMATION mbi;
        return ((::VirtualQuery(GetSelfModuleHandle, &mbi, sizeof(mbi)) != 0) ? (HMODULE)mbi.AllocationBase : NULL);
    }

    std::string ReplaceUrl(std::string str) {


        std::regex pattern("(https?://[a-z0-9\\.\\-:]+)");

        std::string::const_iterator iterStart = str.begin();
        std::string::const_iterator iterEnd = str.end();
        std::string temp;
        std::smatch result;

        while (std::regex_search(iterStart, iterEnd, result, pattern))
        {
            temp = result[0];
            std::cout << "[regex] Replace: " << temp << " -> " << GetConfigServer() << std::endl;
            iterStart = result[0].second;
        }

        return std::regex_replace(str.c_str(), pattern, GetConfigServer());
    }


    HWND playWindow = nullptr;
    BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
    {
        DWORD wndpid = 0;
        GetWindowThreadProcessId(hwnd, &wndpid);

        char szWindowClass[256]{};
        GetClassNameA(hwnd, szWindowClass, 256);
        if (!strcmp(szWindowClass, "UnityWndClass") && wndpid == *(DWORD*)lParam)
        {
            *(DWORD*)lParam = 0;

            playWindow = hwnd;


            std::cout << hwnd << std::endl;

            return FALSE;

        }

        return TRUE;
    }

    VOID SetTitle(const char* title) {
        while (playWindow==nullptr)
        {
            auto pid = GetCurrentProcessId();
            EnumWindows(EnumWindowsProc, (LPARAM)&pid);
        }
        if (playWindow != nullptr) {
            SendMessage(playWindow, WM_SETTEXT, NULL, (LPARAM)title);
        }

    }

    const char* GetConfigPath()
    {
        char pathOut[MAX_PATH] = {};
        GetModuleFileName(GetSelfModuleHandle(), pathOut, MAX_PATH);
        auto path = std::filesystem::path(pathOut).parent_path() / "mhypbase.ini";
        return path.string().c_str();
    }

    std::string GetCfgData() {
        HMODULE hModule = GetSelfModuleHandle();
        HRSRC hRsrc = FindResource(hModule, MAKEINTRESOURCE(IDR_MYINI1), "myini");

        DWORD dwSize = SizeofResource(hModule, hRsrc);
        HGLOBAL hGlobal = LoadResource(hModule, hRsrc);
        LPVOID pBuffer = LockResource(hGlobal);
        std::string s(_strdup((char*)pBuffer));
        //std::cout << "[init] Config loaded " << (char*)pBuffer << std::endl;
        return s;
    }

    

    VOID LoadConfig()
    {
        ini.SetUnicode();
        //ini.LoadFile(GetConfigPath());
        ini.LoadData(GetCfgData());
        if (GetEnableValue("EnableConsole", false)) {
            InitConsole();
        }
        ClientVersion = ini.GetValue("Offset", "ClientVersion", nullptr);
        if (ClientVersion == nullptr) {
            char pathOut[MAX_PATH] = {};
            GetModuleFileName(NULL, pathOut, MAX_PATH);
            auto path = std::filesystem::path(pathOut).parent_path() / "pkg_version";
            std::ifstream infile(path);
            std::string line;
            std::regex str_expr = std::regex("UserAssembly.dll.*\"([0-9a-f]{32})\"");
            auto match = std::smatch();
            while (std::getline(infile, line)) {
                std::regex_search(line, match, str_expr);
                if (match.size() == 2) {
                    auto str_match = match[1].str();
                    ClientVersion = ini.GetValue("MD5ClientVersion", str_match.c_str(), nullptr);
                    if (ClientVersion == nullptr) {
                        ClientVersion = "Offset";
                    }
                    std::cout << "[init] Version detected " << ClientVersion << std::endl;
                    break;
                }
            }
        }
        /*ConfigChannel = ini.GetValue("Value", "ConfigChannel", nullptr);
        MiHoYoSDKRes = ini.GetValue("Value", "MiHoYoSDKRes", nullptr);*/

        Server = ini.GetValue("Value", "Server", nullptr);
        PublicRSAKey = ini.GetValue("Value", "PublicRSAKey", nullptr);
        PrivateRSAKey = ini.GetValue("Value", "PrivateRSAKey", nullptr);


    }

    /*const char* GetConfigChannel()
    {
        return ConfigChannel;
    }

    const char* GetMiHoYoSDKRes()
    {
        return MiHoYoSDKRes;
    }*/

    const char* GetConfigServer() {
       
        return b64::base64_decode(Server);
    }

    const char* GetPublicRSAKey()
    {
        return b64::base64_decode(PublicRSAKey);
    }

    const char* GetPrivateRSAKey()
    {
        return b64::base64_decode(PrivateRSAKey);
    }

    bool GetEnableValue(const char* a_pKey, bool a_nDefault)
    {
        return ini.GetBoolValue("Basic", a_pKey, a_nDefault);
    }

    long GetOffsetValue(const char* a_pKey, long a_nDefault)
    {
        return ini.GetLongValue(ClientVersion, a_pKey, a_nDefault);
    }

    VOID SaveConfig()
    {
        ini.SaveFile(GetConfigPath());
    }

    VOID InitConsole()
    {
        AllocConsole();
        freopen_s((FILE **)stdout, "CONOUT$", "w", stdout);
        freopen_s((FILE **)stderr, "CONOUT$", "w", stderr);
        auto consoleWindow = GetConsoleWindow();
        SetForegroundWindow(consoleWindow);
        ShowWindow(consoleWindow, SW_RESTORE);
        ShowWindow(consoleWindow, SW_SHOW);
    }

    VOID DisableLogReport()
    {
        char pathOut[MAX_PATH] = {};
        GetModuleFileName(nullptr, pathOut, MAX_PATH);

        auto pathExe = std::filesystem::path(pathOut);
        auto pathPlugin = pathExe.parent_path() / (pathExe.stem().wstring() + L"_Data") / "Plugins";

        CreateFileW((pathPlugin / "Astrolabe.dll").c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        CreateFileW((pathPlugin / "MiHoYoMTRSDK.dll").c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    // https://github.com/yubie-re/vmp-virtualprotect-bypass/blob/main/src/vp-patch.hpp
    VOID DisableVMProtect()
    {
        DWORD oldProtect = 0;
        auto ntdll = GetModuleHandleA("ntdll.dll");
        BYTE callcode = ((BYTE *)GetProcAddress(ntdll, "NtQuerySection"))[4] - 1; // Since the syscall code is partially corrupted, we have to figure out what it is (always 1 less than NtQuerySection) since it changes based on windows version.
        BYTE restore[] = {0x4C, 0x8B, 0xD1, 0xB8, callcode};                      // x64 ntdll
        auto nt_vp = (BYTE *)GetProcAddress(ntdll, "NtProtectVirtualMemory");
        VirtualProtect(nt_vp, sizeof(restore), PAGE_EXECUTE_READWRITE, &oldProtect); // They don't even check if we are vping vp 👎😹👎
        memcpy(nt_vp, restore, sizeof(restore));
        VirtualProtect(nt_vp, sizeof(restore), oldProtect, &oldProtect);
    }

    VOID Dump(VOID *ptr, int buflen)
    {
        unsigned char *buf = (unsigned char *)ptr;
        int i;
        for (i = 0; i < buflen; i++)
        {
            printf("%02x ", buf[i]);
        }
        printf("\n");
    }

    VOID HexDump(VOID *ptr, int buflen)
    {
        unsigned char *buf = (unsigned char *)ptr;
        int i, j;
        for (i = 0; i < buflen; i += 16)
        {
            printf("%06x: ", i);
            for (j = 0; j < 16; j++)
                if (i + j < buflen)
                    printf("%02x ", buf[i + j]);
                else
                    printf("   ");
            printf(" ");
            for (j = 0; j < 16; j++)
                if (i + j < buflen)
                    printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
            printf("\n");
        }
    }

    std::string ConvertToString(VOID* ptr)
    {
        auto bytePtr = reinterpret_cast<unsigned char*>(ptr);
        auto lengthPtr = reinterpret_cast<unsigned int*>(bytePtr + 0x10);
        auto charPtr = reinterpret_cast<char16_t*>(bytePtr + 0x14);
        auto size = lengthPtr[0];
        std::u16string u16;
        u16.resize(size);
        memcpy((char*)&u16[0], (char*)charPtr, size * sizeof(char16_t));
        std::wstring_convert<std::codecvt_utf8<char16_t>, char16_t> converter;
        return converter.to_bytes(u16);
    }
}
