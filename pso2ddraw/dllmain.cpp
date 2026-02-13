#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <detours.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <mutex>
#include <nlohmann/json.hpp>

//logging
std::mutex logMutex;

using json = nlohmann::json;

struct Redirection {
    std::string original_hostname;
    std::string target_ip;
};

struct HttpRedirect {
    std::string match_substring;
    std::string replace_with;
};

struct BrowserRedirect {
    std::string match_url;
    std::string replace_url;
};

std::vector<Redirection> hostnameRedirections;
std::vector<HttpRedirect> httpRedirects;
std::vector<BrowserRedirect> browserRedirects;
static std::string defaultTargetIp;
const char* saveip = "";
bool loaded = false;

void Log(const char* msg)
{
    std::lock_guard<std::mutex> lock(logMutex);
    std::ofstream f("ddraw_log.txt", std::ios::app);
    if (f.is_open())
        f << msg << std::endl;
}

void LoadRedirectionsFromJson(const std::string& filename)
{
    std::ifstream file(filename);
    if (!file.is_open()) {
        Log(("[Error] Failed to open JSON file: " + filename).c_str());
        return;
    }

    json j;
    try {
        file >> j;
    }
    catch (const json::parse_error& e) {
        std::string err = "[Error] JSON parse error: ";
        err += e.what();
        Log(err.c_str());
        return;
    }

    // Load default IP
    if (j.contains("default_target_ip") && j["default_target_ip"].is_string()) {
        defaultTargetIp = j["default_target_ip"].get<std::string>();
        Log(("[Info] Default target IP: " + defaultTargetIp).c_str());
    }
    else {
        defaultTargetIp.clear();
    }

    // Trim helper lambda (avoids npos + 1 crash!)
    auto trim = [](std::string& s) {
        const char* ws = " \r\n\t";
        auto pos = s.find_last_not_of(ws);
        if (pos != std::string::npos)
            s.erase(pos + 1);
        };

    // Hostname redirects
    hostnameRedirections.clear();
    if (j.contains("redirects") && j["redirects"].is_array()) {
        for (const auto& item : j["redirects"]) {
            if (item.contains("original_hostname") && item.contains("target_ip")) {
                Redirection r;
                r.original_hostname = item["original_hostname"].get<std::string>();
                r.target_ip = item["target_ip"].get<std::string>();
                trim(r.original_hostname);
                trim(r.target_ip);
                hostnameRedirections.push_back(r);
            }
        }
    }

    // HTTP redirects
    httpRedirects.clear();
    if (j.contains("http_redirects") && j["http_redirects"].is_array()) {
        for (const auto& item : j["http_redirects"]) {
            if (item.contains("match_substring") && item.contains("replace_with")) {
                HttpRedirect r;
                r.match_substring = item["match_substring"].get<std::string>();
                r.replace_with = item["replace_with"].get<std::string>();
                httpRedirects.push_back(r);
            }
        }
    }

    // Browser redirects
    browserRedirects.clear();
    if (j.contains("browser_redirects") && j["browser_redirects"].is_array()) {
        for (const auto& item : j["browser_redirects"]) {
            if (item.contains("match_substring") && item.contains("replace_with")) {
                BrowserRedirect r;
                r.match_url = item["match_substring"].get<std::string>();
                r.replace_url = item["replace_with"].get<std::string>();
                browserRedirects.push_back(r);
            }
        }
    }

    // Summary
    {
        std::string msg = "[Info] Loaded ";
        msg += std::to_string(hostnameRedirections.size()) + " hostname redirection(s), ";
        msg += std::to_string(httpRedirects.size()) + " HTTP redirect(s)";
        Log(msg.c_str());
    }

    Log("Loaded JSON");
}


bool GetRedirectIP(const std::string& hostname, std::string& out_ip)
{
    for (const auto& redir : hostnameRedirections) {
        if (_stricmp(hostname.c_str(), redir.original_hostname.c_str()) == 0) {
            out_ip = redir.target_ip;
            return true;
        }
    }
    return false;
}

std::string ApplyHttpRedirect(const std::string& fullUrl)
{
    for (const auto& redirect : httpRedirects) {
        size_t pos = fullUrl.find(redirect.match_substring);
        if (pos != std::string::npos) {
            std::string newUrl = fullUrl;
            newUrl.replace(pos, redirect.match_substring.length(), redirect.replace_with);
            return newUrl;
        }
    }
    return fullUrl;
}

// --- getaddrinfo hook ---
typedef int (WINAPI* GetaddrinfoFn)(const char* nodename, const char* servname, const struct addrinfo* hints, struct addrinfo** res);
static GetaddrinfoFn orig_getaddrinfo = nullptr;

int WINAPI getaddrinfo_hook(
    const char* nodename,
    const char* servname,
    const struct addrinfo* hints,
    struct addrinfo** res)
{

    

    const char* fallback_ip = "127.0.0.1";
    fallback_ip = defaultTargetIp.c_str();
    std::string redirect_ip;
    const char* use_ip = fallback_ip;

    Log(saveip);
    Log(fallback_ip);
    Log((std::string("[getaddrinfo called] nodename=") + (nodename ? nodename : "<null>")).c_str());

    // Step 0: Bypass if nodename is already the redirect IP


    if (nodename && strcmp(nodename, fallback_ip) == 0) {
        Log((std::string("[Bypass Redirect] Already IP: ") + nodename).c_str());
        return orig_getaddrinfo(nodename, servname, hints, res);
    }

    if (nodename && GetRedirectIP(nodename, redirect_ip)) {
        use_ip = redirect_ip.c_str();
        std::cout << "[Redirect Hostname] " << nodename << " → " << use_ip << std::endl;
        Log((std::string("[Redirect Hostname] ") + nodename + " -> " + use_ip).c_str());
    }
    else {
        if (!use_ip || !*use_ip)
            use_ip = nodename;  // temporary forced IP
        use_ip = fallback_ip;

        //use_ip = redirect_ip.empty() ? fallback_ip : redirect_ip.c_str();
        
        Log((std::string("[Fallback Redirect] ") +
            (nodename ? nodename : "<null>") +
            " -> " + use_ip).c_str());
        std::cout << "[Fallback Redirect] " << (nodename ? nodename : "<null>") << " → " << use_ip << std::endl;
    }

    char* new_host = _strdup(use_ip);
    saveip = _strdup(fallback_ip);
    int result = orig_getaddrinfo(new_host, servname, hints, res);
    //free(new_host);
    
    return result;
}




//// Thread-safe logging
//std::mutex logMutex;
//void LogRedirect(const std::string& message)
//{
//    std::lock_guard<std::mutex> lock(logMutex);
//    std::ofstream log("redirect.log", std::ios::app);
//    if (log.is_open()) {
//        // Add timestamp
//        auto now = std::chrono::system_clock::now();
//        auto time = std::chrono::system_clock::to_time_t(now);
//        log << std::put_time(std::localtime(&time), "[%Y-%m-%d %H:%M:%S] ") << message << std::endl;
//    }
//}


//// --- WinHttpConnect hook ---
//typedef HINTERNET(WINAPI* WinHttpConnectFn)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
//static WinHttpConnectFn orig_WinHttpConnect = nullptr;
//
//HINTERNET WINAPI WinHttpConnect_Hook(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved)
//{
//    std::wstring originalW(pswzServerName ? pswzServerName : L"");
//    std::string original(originalW.begin(), originalW.end());
//
//    std::string redirect_ip;
//    LPCWSTR final_host = pswzServerName;
//
//    static std::wstring wide_redirect; // persistent storage
//
//    if (!original.empty() && GetRedirectIP(original, redirect_ip)) {
//        wide_redirect.assign(redirect_ip.begin(), redirect_ip.end());
//        final_host = wide_redirect.c_str();
//        //std::wcout << L"[WinHTTP Redirect] " << originalW << L" → " << wide_redirect << std::endl;
//    }
//    else if (!defaultTargetIp.empty()) {
//        wide_redirect.assign(defaultTargetIp.begin(), defaultTargetIp.end());
//        final_host = wide_redirect.c_str();
//        //std::wcout << L"[WinHTTP Fallback] " << originalW << L" → " << wide_redirect << std::endl;
//        LogRedirect(original + " → " + redirect_ip + " [WinHTTP Redirect]");
//    }
//
//    return orig_WinHttpConnect(hSession, final_host, nServerPort, dwReserved);
//}

// --- WinHttpOpenRequest hook ---
typedef HINTERNET(WINAPI* WinHttpOpenRequestFn)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
static WinHttpOpenRequestFn orig_WinHttpOpenRequest = nullptr;

HINTERNET WINAPI WinHttpOpenRequest_Hook(
    HINTERNET hConnect,
    LPCWSTR pwszVerb,
    LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion,
    LPCWSTR pwszReferrer,
    LPCWSTR* ppwszAcceptTypes,
    DWORD dwFlags)
{
    std::wstring objectNameW = pwszObjectName ? pwszObjectName : L"";
    std::string objectNameA(objectNameW.begin(), objectNameW.end());

    std::string redirected = ApplyHttpRedirect(objectNameA);
    if (redirected != objectNameA) {
        std::cout << "[HTTP Redirect] " << objectNameA << " → " << redirected << std::endl;
        std::wstring wideRedirected(redirected.begin(), redirected.end());
        return orig_WinHttpOpenRequest(hConnect, pwszVerb, wideRedirected.c_str(), pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
    }

    return orig_WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
}

std::string ApplyBrowserRedirect(const std::string& commandLine)
{
    for (const auto& redirect : browserRedirects) {
        size_t pos = commandLine.find(redirect.match_url);
        if (pos != std::string::npos) {
            std::string newCmd = commandLine;
            newCmd.replace(pos, redirect.match_url.length(), redirect.replace_url);
            return newCmd;
        }
    }
    return commandLine;
}


typedef BOOL(WINAPI* CreateProcessW_Fn)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);

static CreateProcessW_Fn orig_CreateProcessW = nullptr;

BOOL WINAPI CreateProcessW_Hook(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    std::wstring cmdW = lpCommandLine ? lpCommandLine : L"";
    std::string cmdA(cmdW.begin(), cmdW.end());

    std::string redirected = ApplyBrowserRedirect(cmdA);
    if (redirected != cmdA) {
        std::cout << "[Browser Redirect] " << cmdA << " → " << redirected << std::endl;
        std::wstring wideRedirected(redirected.begin(), redirected.end());

        // Need to copy into a writable buffer for CreateProcessW
        std::vector<wchar_t> mutableCmd(wideRedirected.begin(), wideRedirected.end());
        mutableCmd.push_back(L'\0');

        return orig_CreateProcessW(
            lpApplicationName,
            mutableCmd.data(),
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);
    }

    return orig_CreateProcessW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);
}

//trying to hook lua
// Change __cdecl to __thiscall
typedef void(__thiscall* t_LuaHeaderCheck)(int L, unsigned int** zio_ptr);
t_LuaHeaderCheck o_LuaHeaderCheck = nullptr;

// Use __fastcall as a workaround for standalone functions to handle ECX
void __fastcall h_LuaHeaderCheck(int L, void* edx_unused, unsigned int** zio_ptr) {
    __try {
        if (zio_ptr && *zio_ptr) {
            unsigned int* scriptData = *zio_ptr;
            // 0x61754c1b is the "\x1bLua" magic header
            if (scriptData && !IsBadReadPtr(scriptData, 4) && *scriptData == 0x61754c1b) {
                printf("[+] Lua Script Pointer: %p\n", (void*)scriptData);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return o_LuaHeaderCheck(L, zio_ptr);
}















// Forward declaration
DWORD WINAPI InitHookThread(LPVOID lpParam);
DWORD WINAPI LoaderThread(LPVOID)
{

    
    return 0;
}

// --- DllMain ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        // Prevent thread notifications BEFORE creating new threads
        DisableThreadLibraryCalls(hModule);

        // Create hook setup thread
        {
            HANDLE hThread = CreateThread(NULL, 0, InitHookThread, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);
        }

        
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        // Clean unhook
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach((PVOID*)&orig_getaddrinfo, getaddrinfo_hook);
        DetourDetach((PVOID*)&orig_WinHttpOpenRequest, WinHttpOpenRequest_Hook);
        DetourDetach((PVOID*)&orig_CreateProcessW, CreateProcessW_Hook);
        DetourTransactionCommit();
    }

    return TRUE;
}



// --- Hook initialization thread ---
DWORD WINAPI InitHookThread(LPVOID lpParam)
{
    std::ofstream logFile("ddraw_log.txt", std::ios::trunc);
    logFile.close();
    while (!GetModuleHandleA("Ws2_32.dll")) {
        Sleep(10); // just poll safely
    }
    HMODULE ws2 = GetModuleHandleA("Ws2_32.dll");
    HMODULE winhttp = GetModuleHandleA("winhttp.dll");

    // Calculate Dynamic Address
    uintptr_t gameBase = (uintptr_t)GetModuleHandleA(NULL);
    uintptr_t offset = 0x04F8FBD0; // Your Ghidra Offset
    o_LuaHeaderCheck = (t_LuaHeaderCheck)(gameBase + offset);


    orig_getaddrinfo = (GetaddrinfoFn)GetProcAddress(ws2, "getaddrinfo");
    orig_WinHttpOpenRequest = (WinHttpOpenRequestFn)GetProcAddress(winhttp, "WinHttpOpenRequest");
    orig_CreateProcessW = (CreateProcessW_Fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessW");

    if (!orig_getaddrinfo || !orig_WinHttpOpenRequest || !orig_CreateProcessW) return 0;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)o_LuaHeaderCheck, h_LuaHeaderCheck);
    DetourAttach((PVOID*)&orig_getaddrinfo, getaddrinfo_hook);
    DetourAttach((PVOID*)&orig_CreateProcessW, CreateProcessW_Hook);
    DetourAttach((PVOID*)&orig_WinHttpOpenRequest, WinHttpOpenRequest_Hook);
    DetourTransactionCommit();

    LoadRedirectionsFromJson("redirects.json");

    //std::ofstream("hook_log.txt", std::ios::app) << "Hooks installed\n";

    return 0;
}

