/*
 * MSWSOCK specific functions
 *
 * Copyright (C) 2003 André Johansen
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winsock2.h"
#include "mswsock.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(mswsock);

static LPFN_ACCEPTEX acceptex_fn;
static LPFN_GETACCEPTEXSOCKADDRS acceptexsockaddrs_fn;
static LPFN_TRANSMITFILE transmitfile_fn;
static BOOL initialised;

/* Get pointers to the ws2_32 implementations.
 * NOTE: This assumes that ws2_32 contains only one implementation
 * of these functions, i.e. that you cannot get different functions
 * back by passing another socket in. If that ever changes, we'll need
 * to think about associating the functions with the socket and
 * exposing that information to this dll somehow.
 */
static void get_fn(SOCKET s, GUID* guid, FARPROC* fn)
{
    FARPROC func;
    DWORD len;
    if (!WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, guid, sizeof(*guid),
                  &func, sizeof(func), &len, NULL, NULL))
        *fn = func;
}

static void get_fn_pointers(SOCKET s)
{
    GUID acceptex_guid = WSAID_ACCEPTEX;
    GUID acceptexsockaddrs_guid = WSAID_GETACCEPTEXSOCKADDRS;
    GUID transmitfile_guid = WSAID_TRANSMITFILE;

    get_fn(s, &acceptex_guid, (FARPROC*)&acceptex_fn);
    get_fn(s, &acceptexsockaddrs_guid, (FARPROC*)&acceptexsockaddrs_fn);
    get_fn(s, &transmitfile_guid, (FARPROC*)&transmitfile_fn);
    initialised = TRUE;
}

/***********************************************************************
 *		AcceptEx (MSWSOCK.@)
 *
 * Accept a new connection, retrieving the connected addresses and initial data.
 *
 * listener       [I] Listening socket
 * acceptor       [I] Socket to accept on
 * dest           [O] Destination for initial data
 * dest_len       [I] Size of dest in bytes
 * local_addr_len [I] Number of bytes reserved in dest for local address
 * rem_addr_len   [I] Number of bytes reserved in dest for remote address
 * received       [O] Destination for number of bytes of initial data
 * overlapped     [I] For asynchronous execution
 *
 * RETURNS
 * Success: TRUE
 * Failure: FALSE. Use WSAGetLastError() for details of the error.
 */
BOOL WINAPI AcceptEx(SOCKET listener, SOCKET acceptor, PVOID dest, DWORD dest_len,
                     DWORD local_addr_len, DWORD rem_addr_len, LPDWORD received,
                     LPOVERLAPPED overlapped)
{
    if (!initialised)
        get_fn_pointers(acceptor);

    if (!acceptex_fn)
        return FALSE;

    return acceptex_fn(listener, acceptor, dest, dest_len, local_addr_len,
                       rem_addr_len, received, overlapped);
}

/***********************************************************************
 *		GetAcceptExSockaddrs (MSWSOCK.@)
 *
 * Get information about an accepted socket.
 *
 * data           [O] Destination for the first block of data from AcceptEx()
 * data_len       [I] length of data in bytes
 * local_len      [I] Bytes reserved for local addrinfo
 * rem_len        [I] Bytes reserved for remote addrinfo
 * local_addr     [O] Destination for local sockaddr
 * local_addr_len [I] Size of local_addr
 * rem_addr       [O] Destination for remote sockaddr
 * rem_addr_len   [I] Size of rem_addr
 *
 * RETURNS
 *  Nothing.
 */
VOID WINAPI GetAcceptExSockaddrs(PVOID data, DWORD data_len, DWORD local_len, DWORD rem_len,
                                 struct sockaddr **local_addr, LPINT local_addr_len,
                                 struct sockaddr **rem_addr, LPINT rem_addr_len)
{
    if (acceptexsockaddrs_fn)
        acceptexsockaddrs_fn(data, data_len, local_len, rem_len,
                             local_addr, local_addr_len, rem_addr, rem_addr_len);
}


/***********************************************************************
 *		TransmitFile (MSWSOCK.@)
 *
 * Transmit a file over a socket.
 *
 * PARAMS
 * s          [I] Handle to a connected socket
 * file       [I] Opened file handle for file to send
 * total_len  [I] Total number of file bytes to send
 * chunk_len  [I] Chunk size to send file in (0=default)
 * overlapped [I] For asynchronous operation
 * buffers    [I] Head/tail data, or NULL if none
 * flags      [I] TF_ Flags from mswsock.h
 *
 * RETURNS
 * Success: TRUE
 * Failure: FALSE. Use WSAGetLastError() for details of the error.
 */
BOOL WINAPI TransmitFile(SOCKET s, HANDLE file, DWORD total_len,
                         DWORD chunk_len, LPOVERLAPPED overlapped,
                         LPTRANSMIT_FILE_BUFFERS buffers, DWORD flags)
{
    if (!initialised)
        get_fn_pointers(s);

    if (!transmitfile_fn)
        return FALSE;

    return transmitfile_fn(s, file, total_len, chunk_len, overlapped, buffers, flags);
}

/***********************************************************************
 *		WSARecvEx (MSWSOCK.@)
 */
INT WINAPI WSARecvEx(
	SOCKET s,   /* [in] Descriptor identifying a connected socket */
	char *buf,  /* [out] Buffer for the incoming data */
	INT len,    /* [in] Length of buf, in bytes */
        INT *flags) /* [in/out] Indicator specifying whether the message is
	               fully or partially received for datagram sockets */
{
    FIXME("not implemented\n");
    
    return SOCKET_ERROR;
}

/***********************************************************************
 * Base service provider (WSPStartup)
 *
 * mswsock.dll acts as the base transport provider for the builtin
 * protocols (TCP/IP, UDP, IPv6, IPX, Bluetooth).  Layered providers
 * (LSPs, e.g. SSLVPNRedirector.dll) resolve the base provider via
 * WSCGetProviderPath() which returns this DLL, then call its
 * WSPStartup() to obtain a WSPPROC_TABLE.  This implementation fills
 * that table so LSPs can initialize successfully.
 *
 * The standard WSPStartup prototype passes the WSPUPCALLTABLE struct
 * BY VALUE.  On 32-bit x86 that expands to 15 pointer parameters, so
 * the full signature is 19 parameters (wVersion, lpWSPData,
 * lpProtocolInfo, 15 upcalls, lpProcTable).  We accept that exact
 * layout.  The upcall table members are unused here (the base provider
 * does not need to call back into winsock), so they are ignored.
 */

#define WSPDESCRIPTION_LEN 255

typedef struct _LSP_WSPDATA
{
    WORD  wVersion;
    WORD  wHighVersion;
    WCHAR szDescription[WSPDESCRIPTION_LEN + 1];
} LSP_WSPDATA, *LSP_LPWSPDATA;

typedef struct _WSPPROC_TABLE
{
    void *lpWSPAccept;
    void *lpWSPAddressToString;
    void *lpWSPAsyncSelect;
    void *lpWSPBind;
    void *lpWSPCancelBlockingCall;
    void *lpWSPCleanup;
    void *lpWSPCloseSocket;
    void *lpWSPConnect;
    void *lpWSPDuplicateSocket;
    void *lpWSPEnumNetworkEvents;
    void *lpWSPEventSelect;
    void *lpWSPGetOverlappedResult;
    void *lpWSPGetPeerName;
    void *lpWSPGetSockName;
    void *lpWSPGetSockOpt;
    void *lpWSPGetQOSByName;
    void *lpWSPIoctl;
    void *lpWSPJoinLeaf;
    void *lpWSPListen;
    void *lpWSPRecv;
    void *lpWSPRecvDisconnect;
    void *lpWSPRecvFrom;
    void *lpWSPSelect;
    void *lpWSPSend;
    void *lpWSPSendDisconnect;
    void *lpWSPSendTo;
    void *lpWSPSetSockOpt;
    void *lpWSPShutdown;
    void *lpWSPSocket;
    void *lpWSPStringToAddress;
} WSPPROC_TABLE, *LPWSPPROC_TABLE;

/* Simple WSP wrappers that bridge the SPI calling convention to the
 * corresponding ws2_32 API.  Each wrapper reports the resulting error
 * through lpErrno. */

static int WINAPI base_CloseSocket( SOCKET s, int *lpErrno )
{
    int ret = closesocket( s );
    if (ret == SOCKET_ERROR && lpErrno) *lpErrno = WSAGetLastError();
    return ret;
}

static int WINAPI base_Connect( SOCKET s, const struct sockaddr *name, int namelen,
                                LPWSABUF caller, LPWSABUF callee, LPQOS sqos, LPQOS gqos,
                                int *lpErrno )
{
    int ret = connect( s, name, namelen );
    if (ret == SOCKET_ERROR && lpErrno) *lpErrno = WSAGetLastError();
    return ret;
}

static int WINAPI base_Bind( SOCKET s, const struct sockaddr *name, int namelen, int *lpErrno )
{
    int ret = bind( s, name, namelen );
    if (ret == SOCKET_ERROR && lpErrno) *lpErrno = WSAGetLastError();
    return ret;
}

static int WINAPI base_Listen( SOCKET s, int backlog, int *lpErrno )
{
    int ret = listen( s, backlog );
    if (ret == SOCKET_ERROR && lpErrno) *lpErrno = WSAGetLastError();
    return ret;
}

static SOCKET WINAPI base_Accept( SOCKET s, struct sockaddr *addr, int *addrlen,
                                  void *condfn, void *conddata, int *lpErrno )
{
    SOCKET ret = accept( s, addr, addrlen );
    if (ret == INVALID_SOCKET && lpErrno) *lpErrno = WSAGetLastError();
    return ret;
}

static int WINAPI base_Shutdown( SOCKET s, int how, int *lpErrno )
{
    int ret = shutdown( s, how );
    if (ret == SOCKET_ERROR && lpErrno) *lpErrno = WSAGetLastError();
    return ret;
}

static int WINAPI base_GetPeerName( SOCKET s, struct sockaddr *name, int *namelen, int *lpErrno )
{
    int ret = getpeername( s, name, namelen );
    if (ret == SOCKET_ERROR && lpErrno) *lpErrno = WSAGetLastError();
    return ret;
}

static int WINAPI base_GetSockName( SOCKET s, struct sockaddr *name, int *namelen, int *lpErrno )
{
    int ret = getsockname( s, name, namelen );
    if (ret == SOCKET_ERROR && lpErrno) *lpErrno = WSAGetLastError();
    return ret;
}

static int WINAPI base_GetSockOpt( SOCKET s, int level, int optname,
                                   char *optval, int *optlen, int *lpErrno )
{
    int ret = getsockopt( s, level, optname, optval, optlen );
    if (ret == SOCKET_ERROR && lpErrno) *lpErrno = WSAGetLastError();
    return ret;
}

static int WINAPI base_SetSockOpt( SOCKET s, int level, int optname,
                                   const char *optval, int optlen, int *lpErrno )
{
    int ret = setsockopt( s, level, optname, optval, optlen );
    if (ret == SOCKET_ERROR && lpErrno) *lpErrno = WSAGetLastError();
    return ret;
}

static int WINAPI base_Select( int nfds, fd_set *readfds, fd_set *writefds,
                               fd_set *exceptfds, const struct timeval *timeout,
                               int *lpErrno )
{
    int ret = select( nfds, readfds, writefds, exceptfds, timeout );
    if (ret == SOCKET_ERROR && lpErrno) *lpErrno = WSAGetLastError();
    return ret;
}

static int WINAPI base_Send( SOCKET s, LPWSABUF bufs, DWORD count,
                             DWORD *sent, DWORD flags, void *overlapped,
                             void *routine, int *lpErrno )
{
    DWORD i, total = 0;
    for (i = 0; i < count; i++)
    {
        int ret = send( s, bufs[i].buf, bufs[i].len, flags );
        if (ret == SOCKET_ERROR)
        {
            if (lpErrno) *lpErrno = WSAGetLastError();
            return SOCKET_ERROR;
        }
        total += ret;
    }
    if (sent) *sent = total;
    return 0;
}

static int WINAPI base_Recv( SOCKET s, LPWSABUF bufs, DWORD count,
                             DWORD *recvd, DWORD *flags, void *overlapped,
                             void *routine, int *lpErrno )
{
    DWORD i, total = 0;
    for (i = 0; i < count; i++)
    {
        int ret = recv( s, bufs[i].buf, bufs[i].len, flags ? *flags : 0 );
        if (ret == SOCKET_ERROR)
        {
            if (lpErrno) *lpErrno = WSAGetLastError();
            return SOCKET_ERROR;
        }
        total += ret;
    }
    if (recvd) *recvd = total;
    return 0;
}

static SOCKET WINAPI base_Socket( int af, int type, int protocol,
                                  LPWSAPROTOCOL_INFOW info, void *g, DWORD flags,
                                  int *lpErrno )
{
    SOCKET ret;
    if (info)
    {
        if (af == AF_UNSPEC) af = info->iAddressFamily;
        if (type == 0) type = info->iSocketType;
        if (protocol == 0) protocol = info->iProtocol;
    }
    ret = socket( af, type, protocol );
    if (ret == INVALID_SOCKET && lpErrno) *lpErrno = WSAGetLastError();
    return ret;
}

static int WINAPI base_Cleanup( int *lpErrno )
{
    if (lpErrno) *lpErrno = 0;
    return 0;
}

static int WINAPI base_NotSupported( void *a, void *b, void *c, void *d,
                                     void *e, void *f, void *g, int *lpErrno )
{
    if (lpErrno) *lpErrno = WSAEOPNOTSUPP;
    SetLastError( WSAEOPNOTSUPP );
    return SOCKET_ERROR;
}

static int WINAPI base_NotSupportedSocket( SOCKET s, int *lpErrno )
{
    if (lpErrno) *lpErrno = WSAEOPNOTSUPP;
    SetLastError( WSAEOPNOTSUPP );
    return SOCKET_ERROR;
}

/***********************************************************************
 *		WSPStartup (MSWSOCK.@)
 *
 * Initialise the base service provider and fill the WSPPROC_TABLE.
 */
int WINAPI WSPStartup( WORD wVersionRequested, LSP_LPWSPDATA lpWSPData,
                       LPWSAPROTOCOL_INFOW lpProtocolInfo,
                       void *uc0, void *uc1, void *uc2, void *uc3, void *uc4,
                       void *uc5, void *uc6, void *uc7, void *uc8, void *uc9,
                       void *uc10, void *uc11, void *uc12, void *uc13, void *uc14,
                       LPWSPPROC_TABLE lpProcTable )
{
    TRACE( "(wVersion=%04x lpWSPData=%p lpProtocolInfo=%p lpProcTable=%p)\n",
           wVersionRequested, lpWSPData, lpProtocolInfo, lpProcTable );

    if (!lpWSPData || !lpProcTable)
    {
        SetLastError( WSAEINVAL );
        return WSAEINVAL;
    }
    if (LOBYTE( wVersionRequested ) < 1)
    {
        SetLastError( WSAVERNOTSUPPORTED );
        return WSAVERNOTSUPPORTED;
    }

    if (lpWSPData)
    {
        memset( lpWSPData, 0, sizeof(*lpWSPData) );
        lpWSPData->wVersion = MAKEWORD( 2, 2 );
        lpWSPData->wHighVersion = MAKEWORD( 2, 2 );
        lstrcpynW( lpWSPData->szDescription, L"Wine base transport provider", WSPDESCRIPTION_LEN );
    }

    memset( lpProcTable, 0, sizeof(*lpProcTable) );
    lpProcTable->lpWSPAccept              = base_Accept;
    lpProcTable->lpWSPAddressToString     = base_NotSupported;
    lpProcTable->lpWSPAsyncSelect         = base_NotSupportedSocket;
    lpProcTable->lpWSPBind                = base_Bind;
    lpProcTable->lpWSPCancelBlockingCall  = base_NotSupported;
    lpProcTable->lpWSPCleanup             = base_Cleanup;
    lpProcTable->lpWSPCloseSocket         = base_CloseSocket;
    lpProcTable->lpWSPConnect             = base_Connect;
    lpProcTable->lpWSPDuplicateSocket     = base_NotSupported;
    lpProcTable->lpWSPEnumNetworkEvents   = base_NotSupportedSocket;
    lpProcTable->lpWSPEventSelect         = base_NotSupportedSocket;
    lpProcTable->lpWSPGetOverlappedResult = base_NotSupportedSocket;
    lpProcTable->lpWSPGetPeerName         = base_GetPeerName;
    lpProcTable->lpWSPGetSockName         = base_GetSockName;
    lpProcTable->lpWSPGetSockOpt          = base_GetSockOpt;
    lpProcTable->lpWSPGetQOSByName        = base_NotSupportedSocket;
    lpProcTable->lpWSPIoctl               = base_NotSupportedSocket;
    lpProcTable->lpWSPJoinLeaf            = base_NotSupported;
    lpProcTable->lpWSPListen              = base_Listen;
    lpProcTable->lpWSPRecv                = base_Recv;
    lpProcTable->lpWSPRecvDisconnect      = base_NotSupportedSocket;
    lpProcTable->lpWSPRecvFrom            = base_NotSupported;
    lpProcTable->lpWSPSelect              = base_Select;
    lpProcTable->lpWSPSend                = base_Send;
    lpProcTable->lpWSPSendDisconnect      = base_NotSupportedSocket;
    lpProcTable->lpWSPSendTo              = base_NotSupported;
    lpProcTable->lpWSPSetSockOpt          = base_SetSockOpt;
    lpProcTable->lpWSPShutdown            = base_Shutdown;
    lpProcTable->lpWSPSocket              = base_Socket;
    lpProcTable->lpWSPStringToAddress     = base_NotSupported;

    TRACE( "initialised base provider, WSPSocket=%p WSPConnect=%p\n",
           lpProcTable->lpWSPSocket, lpProcTable->lpWSPConnect );
    return 0;
}
