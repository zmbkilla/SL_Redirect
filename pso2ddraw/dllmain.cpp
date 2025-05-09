#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <detours.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct Redirection {
    std::string original_hostname;
    std::string target_ip;
    
};

std::vector<Redirection> hostnameRedirections;

static std::string defaultTargetIp;

// Modified loader to read the new parameter
void LoadRedirectionsFromJson(const std::string& filename)
{
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open JSON file: " << filename << std::endl;
        return;
    }

    json j;
    file >> j;

    // Read optional default_target_ip
    if (j.contains("default_target_ip") && j["default_target_ip"].is_string()) {
        defaultTargetIp = j["default_target_ip"].get<std::string>();
        std::cout << "[Info] Default target IP: " << defaultTargetIp << std::endl;
    }
    else {
        defaultTargetIp.clear();
    }

    // Now parse your existing array (assuming it's still top‑level array of redirects)
    hostnameRedirections.clear();
    if (j.contains("redirects") && j["redirects"].is_array()) {
        for (const auto& item : j["redirects"]) {
            if (item.contains("original_hostname") && item.contains("target_ip")) {
                Redirection r;
                r.original_hostname = item["original_hostname"].get<std::string>();
                r.target_ip = item["target_ip"].get<std::string>();
                hostnameRedirections.push_back(r);
            }
        }
    }

    std::cout << "[Info] Loaded " << hostnameRedirections.size() << " redirection(s)" << std::endl;
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

typedef int (WINAPI* GetaddrinfoFn)(const char* nodename, const char* servname, const struct addrinfo* hints, struct addrinfo** res);
static GetaddrinfoFn orig_getaddrinfo = nullptr;

int WINAPI getaddrinfo_hook(
    const char* nodename,
    const char* servname,
    const struct addrinfo* hints,
    struct addrinfo** res)
{
    const char* fallback_ip = defaultTargetIp.c_str();  // your redirect server IP
    std::string redirect_ip;
    const char* use_ip = nullptr;

    if (nodename && GetRedirectIP(nodename, redirect_ip)) {
        // Known hostname → use its specific target IP
        use_ip = redirect_ip.c_str();
        std::cout << "[Redirect Hostname] " << nodename << " → " << use_ip << std::endl;
    }
    else {
        // Unknown hostname → use the fallback IP
        use_ip = fallback_ip;
        std::cout << "[Fallback Redirect] "
            << (nodename ? nodename : "<null>")
            << " → " << use_ip << std::endl;
    }

    // Always resolve to use_ip
    char* new_host = _strdup(use_ip);
    int result = orig_getaddrinfo(new_host, servname, hints, res);
    free(new_host);
    return result;
}




BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        LoadRedirectionsFromJson("redirects.json");

        // Hook getaddrinfo
        HMODULE ws2 = GetModuleHandleA("Ws2_32.dll");
        orig_getaddrinfo = (GetaddrinfoFn)GetProcAddress(ws2, "getaddrinfo");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach((PVOID*)&orig_getaddrinfo, getaddrinfo_hook);
        DetourTransactionCommit();
        std::cout << "getaddrinfo hook installed!" << std::endl;
    }
    else if (reason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach((PVOID*)&orig_getaddrinfo, getaddrinfo_hook);
        DetourTransactionCommit();
    }
    return TRUE;
}
