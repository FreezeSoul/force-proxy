#include "stdafx.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "detours.lib")

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    } 

    char addressBuff[MAX_PATH] = "127.0.0.1"; 
    char portBuff[MAX_PATH] = "1080";
    char timeoutBuff[MAX_PATH] = "2";

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        DetourRestoreAfterWith();

        GetEnvironmentVariableA("SOCKS5_PROXY_ADDRESS", addressBuff, sizeof(addressBuff));
        GetEnvironmentVariableA("SOCKS5_PROXY_PORT", portBuff, sizeof(portBuff));
        GetEnvironmentVariableA("SOCKS5_PROXY_TIMEOUT", timeoutBuff, sizeof(timeoutBuff));
        GetEnvironmentVariableA("SOCKS5_PROXY_LOGIN", g_ProxyLogin, sizeof(g_ProxyLogin));
        GetEnvironmentVariableA("SOCKS5_PROXY_PASSWORD", g_ProxyPassword, sizeof(g_ProxyPassword));

        inet_pton(AF_INET, addressBuff, &g_ProxyAddress);
        g_ProxyPort = htons(static_cast<uint16_t>(strtol(portBuff, nullptr, 10)));
        g_ProxyTimeout = static_cast<uint32_t>(strtol(portBuff, nullptr, 10));

        InitHooks();

        break;

    case DLL_PROCESS_DETACH:
        DestroyHooks();
        break;
    }
    return TRUE;
}

