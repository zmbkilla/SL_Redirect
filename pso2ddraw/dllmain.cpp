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

    int port_start = 0; // parsed from original_hostname
    int port_end = 0;   // optional range end (defaults to single port)
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
bool allow_redirect;

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

    // Load default IP
    if (j.contains("allow_redirect") && j["allow_redirect"].is_boolean()) {
        allow_redirect = j["allow_redirect"].get<bool>();
        Log((std::string("[Info] allow_redirect = ") + (allow_redirect ? "true" : "false")).c_str());
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

                // range start = original_hostname (port)
                r.port_start = std::stoi(r.original_hostname);

                // optional range end
                r.port_end = item.contains("port_end")
                    ? item["port_end"].get<int>()
                    : r.port_start;
                hostnameRedirections.push_back(r);
            }
        }
    }

    // HTTP redirects
    httpRedirects.clear();
    if (j.contains("http_redirects") && j["http_redirects"].is_array()) {
        for (const auto& item : j["http_redirects"]) {
            if (item.contains("match_prefix") && item.contains("replace_with")) {
                HttpRedirect r;
                r.match_substring = item["match_prefix"].get<std::string>();
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

bool GetRedirectIP_Range(const std::string& portStr, std::string& out_ip)
{
    int port = atoi(portStr.c_str());

    for (const auto& r : hostnameRedirections)
    {
        int start = std::stoi(r.original_hostname);
        int end = (r.port_end > 0) ? r.port_end : start;

        if (port >= start && port <= end)
        {
            out_ip = r.target_ip;
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

    // Port-based override
    std::string portStr = servname ? servname : "";
    int port = portStr.empty() ? 0 : atoi(portStr.c_str());

    if (allow_redirect && GetRedirectIP_Range(std::to_string(port), redirect_ip))
    {
        //nodename = redirect_ip.c_str();
        Log((std::string("[getaddrinfo redirect] ") + (nodename ? nodename : "<null>") + " -> " + redirect_ip).c_str());
        return orig_getaddrinfo(redirect_ip.c_str(), servname, hints, res);
    }

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
typedef HINTERNET(WINAPI* WinHttpConnectFn)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
static WinHttpConnectFn orig_WinHttpConnect = nullptr;

HINTERNET WINAPI WinHttpConnect_Hook(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved)
{
    std::wstring originalW(pswzServerName ? pswzServerName : L"");
    std::string original(originalW.begin(), originalW.end());

    std::string redirect;
    static std::wstring wide_redirect;
    LPCWSTR final_host = pswzServerName;

    for (const auto& r : httpRedirects)
    {
        if (original.find(r.match_substring) != std::string::npos)
        {
            redirect = r.replace_with;
            break;
        }
    }

    if (!redirect.empty())
    {
        wide_redirect.assign(redirect.begin(), redirect.end());
        final_host = wide_redirect.c_str();
    }
    Log(std::string(final_host, final_host + wcslen(final_host)).c_str());

    return orig_WinHttpConnect(hSession, final_host, nServerPort, dwReserved);
}

// --- WinHttpOpenRequest hook ---
//typedef HINTERNET(WINAPI* WinHttpOpenRequestFn)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
//static WinHttpOpenRequestFn orig_WinHttpOpenRequest = nullptr;
//
//HINTERNET WINAPI WinHttpOpenRequest_Hook(
//    HINTERNET hConnect,
//    LPCWSTR pwszVerb,
//    LPCWSTR pwszObjectName,
//    LPCWSTR pwszVersion,
//    LPCWSTR pwszReferrer,
//    LPCWSTR* ppwszAcceptTypes,
//    DWORD dwFlags)
//{
//    std::wstring objectNameW = pwszObjectName ? pwszObjectName : L"";
//    std::string objectNameA(objectNameW.begin(), objectNameW.end());
//
//    std::string redirected = ApplyHttpRedirect(objectNameA);
//    if (redirected != objectNameA) {
//        std::cout << "[HTTP Redirect] " << objectNameA << " → " << redirected << std::endl;
//        std::wstring wideRedirected(redirected.begin(), redirected.end());
//        return orig_WinHttpOpenRequest(hConnect, pwszVerb, wideRedirected.c_str(), pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
//    }
//
//    return orig_WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
//}

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






typedef BOOL(WINAPI* CryptImportKeyFn)(
    ULONG_PTR hProv,
    const BYTE* pbData,
    DWORD dwDataLen,
    ULONG_PTR hPubKey,
    DWORD dwFlags,
    ULONG_PTR* phKey
    );
static CryptImportKeyFn orig_CryptImportKeyFn = nullptr;


BOOL WINAPI Hook_CryptImportKey(
    ULONG_PTR hProv,
    const BYTE* pbData,
    DWORD dwDataLen,
    ULONG_PTR hPubKey,
    DWORD dwFlags,
    ULONG_PTR* phKey
)
{
    // Example: inspect parameters
    if (pbData == nullptr || dwDataLen == 0)
    {
        return orig_CryptImportKeyFn(
            hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey
        );
    }

    // ---- your custom logic here ----
    const BYTE* dataPtr = pbData;
    DWORD dataLen = dwDataLen;

    // modify dataPtr/dataLen if needed

    std::ifstream file("test.bin", std::ios::binary);

    if (!file)
    {
        std::cout << "Failed to open file\n";
        return 1;
    }

    // get file size
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    // allocate buffer
    std::vector<unsigned char> buffer(size);

    // read file into memory
    file.read(reinterpret_cast<char*>(buffer.data()), size);

    std::cout << "Read " << buffer.size() << " bytes\n";

    // access data
    unsigned char* fdataPtr = buffer.data();
    size_t fdataLen = buffer.size();

    memcpy((void*)dataPtr, &fdataLen, fdataLen);

    // call original
    return orig_CryptImportKeyFn(
        hProv,
        dataPtr,
        dataLen,
        hPubKey,
        dwFlags,
        phKey
    );
}







//end of bs
// Forward declaration
DWORD WINAPI InitHookThread(LPVOID lpParam);
DWORD WINAPI HttpInitThread(LPVOID lpParam);
DWORD WINAPI LoaderThread(LPVOID)
{

    
    return 0;
}

// --- DllMain ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    DisableThreadLibraryCalls(hModule);
    std::ofstream logFile("ddraw_log.txt", std::ios::trunc);
    logFile.close();
    LoadRedirectionsFromJson("redirects.json");

    if (reason == DLL_PROCESS_ATTACH)
    {
        

        // Always start HTTP init (default feature)
        HANDLE hHttpThread = CreateThread(
            NULL, 0, HttpInitThread, NULL, 0, NULL);

        if (hHttpThread)
            CloseHandle(hHttpThread);

        // Conditionally start DNS redirect init
        if (allow_redirect)
        {
            HANDLE hRedirectThread = CreateThread(
                NULL, 0, InitHookThread, NULL, 0, NULL);

            if (hRedirectThread)
                CloseHandle(hRedirectThread);
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        // FULL DLL CLEANUP — always runs if DLL is unloading

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        if (orig_getaddrinfo)
            DetourDetach((PVOID*)&orig_getaddrinfo, getaddrinfo_hook);

        if (orig_WinHttpConnect)
            DetourDetach((PVOID*)&orig_WinHttpConnect, WinHttpConnect_Hook);

        if (orig_CreateProcessW)
            DetourDetach((PVOID*)&orig_CreateProcessW, CreateProcessW_Hook);

        if (orig_CryptImportKeyFn)
            DetourDetach((PVOID*)&orig_CryptImportKeyFn, Hook_CryptImportKey);

        DetourTransactionCommit();
    }

    return TRUE;
}



// --- Hook initialization thread ---
DWORD WINAPI InitHookThread(LPVOID lpParam)
{
    
    
    while (!GetModuleHandleA("Ws2_32.dll")) {
        Sleep(10); // just poll safely
    }
    HMODULE ws2 = GetModuleHandleA("Ws2_32.dll");
    //HMODULE winhttp = GetModuleHandleA("winhttp.dll");
    //HMODULE bcrypt = GetModuleHandleA("bcrypt.dll");



    orig_getaddrinfo = (GetaddrinfoFn)GetProcAddress(ws2, "getaddrinfo");
    //orig_WinHttpOpenRequest = (WinHttpOpenRequestFn)GetProcAddress(winhttp, "WinHttpOpenRequest");
    orig_CreateProcessW = (CreateProcessW_Fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessW");
    //orig_CryptImportKeyFn = (CryptImportKeyFn)GetProcAddress(GetModuleHandleA("bcrypt.dll"), "CryptImportKey");

    //if (!orig_getaddrinfo || !orig_WinHttpOpenRequest || !orig_CreateProcessW) return 0;
    //if (!orig_WinHttpOpenRequest || !orig_CreateProcessW) return 0;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((PVOID*)&orig_getaddrinfo, getaddrinfo_hook);
    DetourAttach((PVOID*)&orig_CreateProcessW, CreateProcessW_Hook);
    //DetourAttach((PVOID*)&orig_WinHttpOpenRequest, WinHttpOpenRequest_Hook);
    //DetourAttach((PVOID*)&orig_CryptImportKeyFn, Hook_CryptImportKey);
    DetourTransactionCommit();

    //std::ofstream("hook_log.txt", std::ios::app) << "Hooks installed\n";

    return 0;
}

DWORD WINAPI HttpInitThread(LPVOID lpParam)
{
    while (!GetModuleHandleA("winhttp.dll"))
        Sleep(10);
    
    HMODULE winhttp = GetModuleHandleA("winhttp.dll");

    orig_WinHttpConnect =
        (WinHttpConnectFn)GetProcAddress(winhttp, "WinHttpConnect");

    if (!orig_WinHttpConnect)
        return 0;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach((PVOID*)&orig_WinHttpConnect, WinHttpConnect_Hook);

    DetourTransactionCommit();

    Log("[HTTP Init] WinHttpConnect hooked");

    return 0;
}

