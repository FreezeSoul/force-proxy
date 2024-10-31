#pragma once

extern IN_ADDR g_ProxyAddress;
extern uint16_t g_ProxyPort;
extern uint32_t g_ProxyTimeout;


int ConnectThroughSocks5(SOCKET s, const struct sockaddr_in* targetAddr, bool nonBlocking);
bool InitializeSocks5UdpAssociation(sockaddr_in* udpProxyAddr);
void EncapsulateUDPPacket(WSABUF* target, char* buf, int len, const sockaddr* lpTo);
void ExtractSockAddr(char* buf, sockaddr* target);