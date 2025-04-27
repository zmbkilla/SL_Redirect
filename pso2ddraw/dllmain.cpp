#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <detours.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Structure for hostname redirection
struct Redirection
{
    std::string original_hostname;  // Hostname we expect
    std::string target_ip;           // IP to redirect to
};

std::vector<Redirection> hostnameRedirections;

// Load JSON redirection file
void LoadRedirectionsFromJson(const std::string& filename)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        std::cerr << "Failed to open JSON file!" << std::endl;
        return;
    }

    json j;
    file >> j;

    hostnameRedirections.clear();
    for (const auto& item : j)
    {
        Redirection redir;
        redir.original_hostname = item["original_hostname"];
        redir.target_ip = item["target_ip"];
        hostnameRedirections.push_back(redir);
    }

    std::cout << "Loaded " << hostnameRedirections.size() << " redirection(s)" << std::endl;
}

// Find redirect IP based on hostname
bool GetRedirectIP(const std::string& hostname, std::string& out_ip)
{
    for (const auto& redir : hostnameRedirections)
    {
        if (_stricmp(hostname.c_str(), redir.original_hostname.c_str()) == 0)
        {
            out_ip = redir.target_ip;
            return true;
        }
    }
    return false;
}

// Original function pointer
typedef int (WINAPI* GetaddrinfoFn)(
    const char* nodename,
    const char* servname,
    const struct addrinfo* hints,
    struct addrinfo** res);

static GetaddrinfoFn orig_getaddrinfo = nullptr;

// Hooked getaddrinfo
int WINAPI getaddrinfo_hook(
    const char* nodename,
    const char* servname,
    const struct addrinfo* hints,
    struct addrinfo** res)
{
    if (nodename)
    {
        std::string redirect_ip;
        if (GetRedirectIP(nodename, redirect_ip))
        {
            std::cout << "[Redirect Hostname] " << nodename << " → " << redirect_ip << std::endl;
            // Instead of nodename, pass the redirected IP address
            return orig_getaddrinfo(redirect_ip.c_str(), servname, hints, res);
        }
    }

    // No redirection, call original
    return orig_getaddrinfo(nodename, servname, hints, res);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        // Load redirection table
        LoadRedirectionsFromJson("redirects.json");

        // Load original function
        HMODULE ws2 = GetModuleHandleA("Ws2_32.dll");
        orig_getaddrinfo = (GetaddrinfoFn)GetProcAddress(ws2, "getaddrinfo");

        // Hook using Detours
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach((PVOID*)&orig_getaddrinfo, getaddrinfo_hook);
        DetourTransactionCommit();

        std::cout << "Hostname hook installed!" << std::endl;
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        // Remove hook
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach((PVOID*)&orig_getaddrinfo, getaddrinfo_hook);
        DetourTransactionCommit();
    }
    return TRUE;
}
