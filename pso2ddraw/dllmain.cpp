#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <detours.h>
#include <iostream>
#include <string>
#include <fstream>
#include <nlohmann/json.hpp>  // Include the nlohmann json header

using json = nlohmann::json;

// Data structure to hold the IP redirections
struct Redirection
{
    std::string original_ip;
    std::string target_ip;
};

std::vector<Redirection> ipRedirections;

// Function to load redirections from a JSON file
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

    // Parse the JSON and populate the redirection vector
    for (auto& item : j)
    {
        Redirection redir;
        redir.original_ip = item["original_ip"];
        redir.target_ip = item["target_ip"];
        ipRedirections.push_back(redir);
    }

    std::cout << "Loaded " << ipRedirections.size() << " redirection(s)" << std::endl;
}

// Originals
typedef int (WINAPI* GetaddrinfoFn)(
    const char* nodename,
    const char* servname,
    const struct addrinfo* hints,
    struct addrinfo** res);
typedef int (WINAPI* ConnectFn)(
    SOCKET s,
    const struct sockaddr* name,
    int namelen);

static GetaddrinfoFn orig_getaddrinfo = nullptr;
static ConnectFn      orig_connect = nullptr;

// Hooked getaddrinfo: swap only the hostname, keep servname (port) intact
int WINAPI getaddrinfo_hook(
    const char* nodename,
    const char* servname,
    const struct addrinfo* hints,
    struct addrinfo** res)
{
    if (nodename)
    {
        for (const auto& redir : ipRedirections)
        {
            if (_stricmp(nodename, redir.original_ip.c_str()) == 0)
            {
                std::cout << "[Redirect] " << nodename << ":" << servname
                    << " → " << redir.target_ip << ":" << servname << std::endl;
                return orig_getaddrinfo(redir.target_ip.c_str(), servname, hints, res);
            }
        }
    }
    return orig_getaddrinfo(nodename, servname, hints, res);
}

// Hooked connect: swap only the IP, preserve original port
int WINAPI connect_hook(
    SOCKET s,
    const struct sockaddr* name,
    int namelen)
{
    if (name && name->sa_family == AF_INET)
    {
        auto addr_in = (sockaddr_in const*)name;
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr_in->sin_addr, ipstr, sizeof(ipstr));
        int origPort = ntohs(addr_in->sin_port);

        // If the IP matches one in the redirection list, perform the redirect
        for (const auto& redir : ipRedirections)
        {
            if (_stricmp(ipstr, redir.original_ip.c_str()) == 0)
            {
                std::cout << "[RedirectConnect] " << ipstr << ":" << origPort
                    << " → " << redir.target_ip << ":" << origPort << std::endl;

                sockaddr_in redirectAddr = {};
                redirectAddr.sin_family = AF_INET;
                redirectAddr.sin_port = htons(origPort);
                inet_pton(AF_INET, redir.target_ip.c_str(), &redirectAddr.sin_addr);

                return orig_connect(s, (sockaddr*)&redirectAddr, sizeof(redirectAddr));
            }
        }
    }
    return orig_connect(s, name, namelen);
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        MessageBoxA(nullptr,
            "Hook DLL loaded! Enjoy Playing Starlight",
            "Info",
            MB_OK | MB_ICONINFORMATION);

        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);

        LoadRedirectionsFromJson("redirects.json");  // Load the JSON file

        HMODULE ws2 = GetModuleHandleA("Ws2_32.dll");
        orig_getaddrinfo = (GetaddrinfoFn)
            GetProcAddress(ws2, "getaddrinfo");
        orig_connect = (ConnectFn)
            GetProcAddress(ws2, "connect");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach((PVOID*)&orig_getaddrinfo, getaddrinfo_hook);
        DetourAttach((PVOID*)&orig_connect, connect_hook);
        DetourTransactionCommit();

        std::cout << "Hooks installed\n";
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach((PVOID*)&orig_getaddrinfo, getaddrinfo_hook);
        DetourDetach((PVOID*)&orig_connect, connect_hook);
        DetourTransactionCommit();

        WSACleanup();
    }
    return TRUE;
}
