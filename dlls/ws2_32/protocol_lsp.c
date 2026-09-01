/*
 * protocol_lsp.c - LSP-aware WSC* function implementations
 *
 * For Wine 10.14 (release-10.14 tag)
 *
 * This file is #included at the end of protocol.c, after the original
 * WSC* stubs are wrapped in #if 0. The parent file already included
 * ws2_32_private.h which provides all needed types.
 *
 * NOTE: This file is NOT compiled separately. It is only included from
 * protocol.c via #include. Do NOT add it to Makefile.in SOURCES.
 *
 * Wine 10.14 WSC* functions (11 total):
 *   WSCEnableNSProvider, WSCGetApplicationCategory, WSCGetProviderInfo,
 *   WSCGetProviderPath, WSCInstallNameSpace, WSCUnInstallNameSpace,
 *   WSCWriteProviderOrder, WSCInstallProvider, WSCDeinstallProvider,
 *   WSCSetApplicationCategory, WSCEnumProtocols
 *
 * NOT in 10.14: WSCEnumProtocols32, WSCInstallProvider64_32
 *
 * LGPL v2.1+
 */

/* lsp.h must always be included - it provides LSP types and function declarations */
#include "lsp.h"

/* Thread-local reentrancy guard for WSCEnumProtocols.
 *
 * SSLVPNRedirector.dll calls WSCEnumProtocols recursively from within
 * its own processing of WSCEnumProtocols results. Each recursion level
 * consumes ~4 KB of stack, eventually overflowing even a 1 MB stack.
 *
 * Fix: detect recursive entry via TLS. On recursive calls, delegate
 * directly to the builtin WSAEnumProtocolsW (which does not call back
 * into WSCEnumProtocols), skipping LSP enumeration entirely.
 */
static DWORD tls_wsc_reentrant = TLS_OUT_OF_INDEXES;

static void ensure_tls_reentrant(void)
{
    if (tls_wsc_reentrant == TLS_OUT_OF_INDEXES)
        tls_wsc_reentrant = TlsAlloc();
}

/* The following guard provides stub macros only when this file is compiled
 * standalone (syntax check). When #included from protocol.c, the parent
 * file already defined WINE_DEFAULT_DEBUG_CHANNEL via wine/debug.h. */
#ifndef WINE_DEFAULT_DEBUG_CHANNEL
#define WINE_DEFAULT_DEBUG_CHANNEL(winsock) \
    static void __wine_dbg_##winsock(const char *fmt, ...) { (void)fmt; }
#define TRACE(...) do { } while(0)
#define WARN(...)  do { } while(0)
#define ERR(...)   do { } while(0)
#define debugstr_guid(g) "(guid)"
#define debugstr_w(s)   "(wstr)"
#endif

/* =====================================================================
 * WSCEnableNSProvider
 * ===================================================================== */
int WINAPI WSCEnableNSProvider( GUID *provider, BOOL enable )
{
    TRACE( "(%s %d)\n", debugstr_guid(provider), enable );
    if (!provider) { SetLastError( WSAEFAULT ); return -1; }
    return lsp_enable_provider( provider, enable );
}

/* =====================================================================
 * WSCGetApplicationCategory
 * ===================================================================== */
int WINAPI WSCGetApplicationCategory( const WCHAR *path, DWORD path_len,
                                      const WCHAR *extra, DWORD extra_len,
                                      DWORD *category, int *errcode )
{
    TRACE( "(%s %lu %s %lu %p %p)\n",
           debugstr_w(path), path_len, debugstr_w(extra),
           extra_len, category, errcode );
    if (!path || !errcode) { if (errcode) *errcode = WSAEFAULT; return -1; }
    *category = 1;
    *errcode = 0;
    return 0;
}

/* =====================================================================
 * WSCGetProviderInfo
 * ===================================================================== */
int WINAPI WSCGetProviderInfo( GUID *provider, WSC_PROVIDER_INFO_TYPE info_type,
                               BYTE *info, size_t *len, DWORD flags, int *errcode )
{
    LSP_PROVIDER_ENTRY *p;
    TRACE( "(%s %#x %p %p %#lx %p)\n",
           debugstr_guid(provider), info_type, info, len, flags, errcode );
    if (!errcode) return -1;
    if (!provider) { *errcode = WSAEFAULT; return -1; }
    lsp_catalog_load();
    p = lsp_find_provider_by_guid( provider );
    if (!p) { *errcode = WSANO_RECOVERY; return -1; }
    if (info_type == ProviderInfoLspCategories)
    {
        DWORD cat = p->info.dwProviderFlags;
        if (len && *len >= sizeof(DWORD) && info)
        { memcpy( info, &cat, sizeof(DWORD) ); *errcode = 0; return 0; }
        if (len) *len = sizeof(DWORD);
        *errcode = WSAEFAULT;
        return -1;
    }
    *errcode = WSAEINVAL;
    return -1;
}

/* =====================================================================
 * Builtin base provider DLL path
 *
 * The LSP (e.g. SSLVPNRedirector.dll) resolves its base provider by:
 *   1. reading ChainEntries[ChainLen-1] (a base catalog entry id),
 *   2. enumerating providers to find the base (ChainLen==1) entry,
 *   3. calling WSCGetProviderPath(base ProviderId GUID) to get the DLL,
 *   4. LoadLibrary + GetProcAddress("WSPStartup") on that DLL.
 *
 * In Wine the base providers (TCP/IP, UDP, IPv6, IPX, Bluetooth) are
 * builtin to ws2_32 and served through mswsock.dll.  WSCGetProviderPath
 * must therefore return the mswsock.dll path for the well-known base
 * provider GUIDs, otherwise the LSP aborts with ERROR_INVALID_PARAMETER
 * (87) at step 3.
 *
 * Returns TRUE and copies the path into 'path' if 'guid' is a builtin
 * base provider; returns FALSE otherwise.
 * ===================================================================== */
static BOOL lsp_get_builtin_base_path( const GUID *guid, WCHAR *path, DWORD path_chars )
{
    static const GUID base_tcp4   = {0xe70f1aa0, 0xab8b, 0x11cf, {0x8c, 0xa3, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}};
    static const GUID base_ip6    = {0xf9eab0c0, 0x26d4, 0x11d0, {0xbb, 0xbf, 0x00, 0xaa, 0x00, 0x6c, 0x34, 0xe4}};
    static const GUID base_ipx    = {0x11058240, 0xbe47, 0x11cf, {0x95, 0xc8, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}};
    static const GUID base_ipx_spx = {0x11058241, 0xbe47, 0x11cf, {0x95, 0xc8, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}};
    static const GUID base_bth    = {0x9fc48064, 0x7298, 0x43e4, {0xb7, 0xbd, 0x18, 0x1f, 0x20, 0x89, 0x79, 0x2a}};
    static const WCHAR mswsock_rel[] = L"mswsock.dll";
    WCHAR windir[MAX_PATH];
    UINT n;

    if (!IsEqualGUID( guid, &base_tcp4 ) && !IsEqualGUID( guid, &base_ip6 ) &&
        !IsEqualGUID( guid, &base_ipx ) && !IsEqualGUID( guid, &base_ipx_spx ) &&
        !IsEqualGUID( guid, &base_bth ))
        return FALSE;

    /* GetSystemDirectoryW already returns "...\windows\system32", so only
     * append the DLL name.  (The previous code appended "system32\mswsock.dll"
     * producing "system32\system32\mswsock.dll", which the LSP's LoadLibrary
     * rejected and WSPStartup failed with ERROR_INVALID_PARAMETER.) */
    n = GetSystemDirectoryW( windir, MAX_PATH );
    if (!n || n >= MAX_PATH) lstrcpyW( windir, L"C:\\windows\\system32" );
    wsprintfW( path, L"%s\\%s", windir, mswsock_rel );
    return TRUE;
}

/* =====================================================================
 * WSCGetProviderPath
 *
 * CRITICAL: VPN installer calls this after WSCInstallProvider.
 * Also called by the LSP during its own WSPStartup to resolve the base
 * provider DLL (mswsock.dll).
 * ===================================================================== */
int WINAPI WSCGetProviderPath( GUID *provider, WCHAR *path, int *len, int *errcode )
{
    LSP_PROVIDER_ENTRY *p;
    DWORD needed;
    WCHAR base_path[MAX_PATH];

    TRACE( "(%s %p %p %p)\n", debugstr_guid(provider), path, len, errcode );
    if (!provider || !len) { if (errcode) *errcode = WSAEFAULT; return -1; }
    if (*len <= 0) { if (errcode) *errcode = WSAEINVAL; return -1; }

    /* Low stack: LSP DLL worker threads run nearly out of stack.  The
     * registry catalog lookup below is too deep for that, but resolving
     * the well-known builtin base providers (mswsock.dll) only needs
     * IsEqualGUID + GetSystemDirectoryW, and looking up an LSP provider
     * by GUID walks only the in-memory catalog - both shallow enough.
     * No TRACE here: the wine debug channel itself would burn stack. */
    if (lsp_stack_low())
    {
        if (lsp_get_builtin_base_path( provider, base_path, MAX_PATH ))
        {
            needed = (wcslen( base_path ) + 1) * sizeof(WCHAR);
            if ((DWORD)*len < needed) { *len = needed; if (errcode) *errcode = WSAEFAULT; return -1; }
            memcpy( path, base_path, needed );
            *len = needed;
            if (errcode) *errcode = 0;
            return 0;
        }
        if (lsp_catalog_loaded())
        {
            p = lsp_find_provider_by_guid( provider );
            if (p && p->dll_path[0])
            {
                needed = (wcslen( p->dll_path ) + 1) * sizeof(WCHAR);
                if ((DWORD)*len < needed) { *len = needed; if (errcode) *errcode = WSAEFAULT; return -1; }
                memcpy( path, p->dll_path, needed );
                *len = needed;
                if (errcode) *errcode = 0;
                return 0;
            }
        }
        if (errcode) *errcode = WSANO_RECOVERY;
        return -1;
    }

    /* 1) Builtin base providers are served by mswsock.dll. */
    if (lsp_get_builtin_base_path( provider, base_path, MAX_PATH ))
    {
        needed = (wcslen( base_path ) + 1) * sizeof(WCHAR);
        if ((DWORD)*len < needed) { *len = needed; if (errcode) *errcode = WSAEFAULT; return -1; }
        memcpy( path, base_path, needed );
        *len = needed;
        if (errcode) *errcode = 0;
        TRACE( "builtin base provider -> %s\n", debugstr_w(path) );
        return 0;
    }

    /* 2) LSP providers registered in the catalog. */
    lsp_catalog_load();
    p = lsp_find_provider_by_guid( provider );
    if (!p)
    {
        TRACE( "Provider %s not found\n", debugstr_guid(provider) );
        if (errcode) *errcode = WSANO_RECOVERY;
        return -1;
    }
    if (!p->dll_path[0]) { if (errcode) *errcode = WSANO_RECOVERY; return -1; }

    needed = (wcslen( p->dll_path ) + 1) * sizeof(WCHAR);
    if ((DWORD)*len < needed) { *len = needed; if (errcode) *errcode = WSAEFAULT; return -1; }

    memcpy( path, p->dll_path, needed );
    *len = needed;
    if (errcode) *errcode = 0;
    TRACE( "-> %s\n", debugstr_w(path) );
    return 0;
}

/* =====================================================================
 * WSCInstallNameSpace
 * ===================================================================== */
int WINAPI WSCInstallNameSpace( WCHAR *identifier, WCHAR *path,
                                DWORD namespace, DWORD version, GUID *provider )
{
    TRACE( "(%s, %s, %#lx, %#lx, %s)\n",
           debugstr_w(identifier), debugstr_w(path),
           namespace, version, debugstr_guid(provider) );
    if (!identifier || !provider) { SetLastError( WSAEINVAL ); return -1; }
    return 0;
}

/* =====================================================================
 * WSCUnInstallNameSpace
 * ===================================================================== */
int WINAPI WSCUnInstallNameSpace( GUID *provider )
{
    TRACE( "(%s)\n", debugstr_guid(provider) );
    if (!provider) { SetLastError( WSAEINVAL ); return -1; }
    return 0;
}

/* =====================================================================
 * WSCWriteProviderOrder
 *
 * CRITICAL: VPN installer calls this to put LSP first in catalog.
 * ===================================================================== */
int WINAPI WSCWriteProviderOrder( DWORD *entry, DWORD number )
{
    TRACE( "(%p, %lu)\n", entry, number );
    if (!entry || !number) { SetLastError( WSAEINVAL ); return -1; }

    /* Delegated to lsp.c to keep g_catalog static */
    return lsp_write_provider_order( entry, number );
}

/* =====================================================================
 * WSCInstallProvider
 *
 * THE key function: VPN installer calls this to register the LSP.
 * ===================================================================== */
int WINAPI WSCInstallProvider( GUID *provider, const WCHAR *path,
                               WSAPROTOCOL_INFOW *protocol_info,
                               DWORD count, int *err )
{
    int ret;
    DWORD i;

    TRACE( "(%s, %s, %p, %lu, %p)\n",
           debugstr_guid(provider), debugstr_w(path),
           protocol_info, count, err );

    if (!provider || !path || !protocol_info || !count)
    { if (err) *err = WSAEFAULT; return -1; }
    if (err) *err = 0;

    lsp_catalog_load();
    ret = lsp_add_provider( provider, path, protocol_info, count );
    if (ret != 0) { if (err) *err = WSANO_RECOVERY; return -1; }

    for (i = 0; i < count; i++)
        TRACE( "  [%lu] %s af=%d type=%d cl=%d\n",
               protocol_info[i].dwCatalogEntryId,
               debugstr_w(protocol_info[i].szProtocol),
               protocol_info[i].iAddressFamily,
               protocol_info[i].iSocketType,
               protocol_info[i].ProtocolChain.ChainLen );

    lsp_catalog_save();
    TRACE( "LSP installed: %s, %lu entries\n", debugstr_guid(provider), count );
    return 0;
}

/* =====================================================================
 * WSCDeinstallProvider
 * ===================================================================== */
int WINAPI WSCDeinstallProvider( GUID *provider, int *err )
{
    TRACE( "(%s, %p)\n", debugstr_guid(provider), err );
    if (!provider) { if (err) *err = WSAEFAULT; return -1; }
    if (err) *err = 0;
    lsp_catalog_load();
    lsp_remove_provider( provider );
    lsp_catalog_save();
    return 0;
}

/* =====================================================================
 * WSCSetApplicationCategory
 * ===================================================================== */
int WINAPI WSCSetApplicationCategory( const WCHAR *path, DWORD len,
                                      const WCHAR *extra, DWORD extralen,
                                      DWORD lspcat, DWORD *prev_lspcat, int *err )
{
    TRACE( "(%s %lu %s %lu %#lx %p)\n",
           debugstr_w(path), len, debugstr_w(extra), extralen, lspcat, prev_lspcat );
    if (!path) { if (err) *err = WSAEFAULT; return -1; }
    if (prev_lspcat) *prev_lspcat = 0;
    if (err) *err = 0;
    return 0;
}

/* =====================================================================
 * WSCEnumProtocols
 *
 * Standard Windows behavior:
 *   info=NULL or buffer too small → return -1, *len = total needed,
 *                                  *err = WSAENOBUFS
 *   buffer OK                → fill LSP first, then builtins,
 *                                  return total count
 * ===================================================================== */
int WINAPI WSCEnumProtocols( int *protocols, WSAPROTOCOL_INFOW *info,
                            DWORD *len, int *err )
{
    DWORD lsp_needed = 0, builtin_needed = 0, total_needed;
    int lsp_count = 0, builtin_count = 0;
    DWORD orig_len;
    BOOL is_reentrant;

    if (!len || !err) return -1;
    *err = 0;
    orig_len = *len;

    /* Reentrancy guard: if WSCEnumProtocols is already active on this
     * thread (e.g. SSLVPNRedirector.dll calls it recursively), delegate
     * directly to the builtin enumeration to avoid unbounded recursion. */
    ensure_tls_reentrant();
    is_reentrant = (TlsGetValue(tls_wsc_reentrant) != NULL);
    TlsSetValue(tls_wsc_reentrant, (LPVOID)1);

    if (is_reentrant)
    {
        int ret = WSAEnumProtocolsW(protocols, info, len);
        if (ret == SOCKET_ERROR) *err = WSAENOBUFS;
        TlsSetValue(tls_wsc_reentrant, NULL);
        return ret;
    }

    /* Stack-light fast path: the catalog is already in memory.
     *
     * SSLVPNRedirector.dll creates worker threads that consume nearly
     * all of their 1 MB stack before calling WSCEnumProtocols.  The old
     * low-stack guard returned 0 protocols on those threads, which made
     * the LSP's WSPStartup fail with ERROR_INVALID_PARAMETER (87).
     * Serving the enumeration directly from memory (no registry access,
     * no provider preload, no wine debug channels) uses only a few
     * hundred bytes of stack, so the LSP receives correct results even
     * on thin threads. */
    if (lsp_catalog_loaded())
    {
        int ret;

        lsp_count = lsp_enum_protocols( protocols, NULL, &lsp_needed, FALSE );
        if (lsp_count < 0) lsp_count = 0;

        builtin_needed = 0;
        sock_enum_protocols_shallow( protocols, NULL, &builtin_needed );

        total_needed = lsp_needed + builtin_needed;
        if (!info || orig_len < total_needed)
        {
            *len = total_needed;
            *err = WSAENOBUFS;
            TlsSetValue(tls_wsc_reentrant, NULL);
            return -1;
        }

        if (lsp_count > 0)
        {
            DWORD lsp_actual = orig_len;
            DWORD remaining;
            int lsp_filled = lsp_enum_protocols( protocols, info, &lsp_actual, FALSE );

            if (lsp_filled < 0) lsp_filled = 0;
            remaining = orig_len - lsp_actual;
            builtin_count = sock_enum_protocols_shallow(
                protocols, (WSAPROTOCOL_INFOW *)((BYTE *)info + lsp_actual), &remaining );
            if (builtin_count >= 0)
            {
                *len = lsp_actual + builtin_count * sizeof(WSAPROTOCOL_INFOW);
                ret = lsp_filled + builtin_count;
            }
            else
            {
                *len = lsp_actual;
                ret = lsp_filled;
            }
        }
        else
        {
            builtin_needed = orig_len;
            builtin_count = sock_enum_protocols_shallow( protocols, info, &builtin_needed );
            if (builtin_count < 0)
            {
                *len = builtin_needed;
                *err = WSAENOBUFS;
                TlsSetValue(tls_wsc_reentrant, NULL);
                return -1;
            }
            *len = builtin_count * sizeof(WSAPROTOCOL_INFOW);
            ret = builtin_count;
        }
        TlsSetValue(tls_wsc_reentrant, NULL);
        return ret;
    }

    TRACE( "(protocols=%p, info=%p, len=%p, err=%p)\n", protocols, info, len, err );

    /* Catalog not in memory yet.  Loading it walks the registry and
     * preloads LSP DLLs (WSPStartup), which needs far more stack than a
     * nearly-exhausted worker thread can provide; bail out so we do not
     * overflow.  In practice the catalog is loaded by the app's first
     * socket call (WSASocketW/WSAStartup), so this only happens when the
     * very first WSC* call originates from an LSP thread. */
    if (lsp_stack_low())
    {
        TRACE("low stack, catalog not loaded -> 0 protocols\n");
        *len = 0;
        *err = 0;
        TlsSetValue(tls_wsc_reentrant, NULL);
        return 0;
    }

    lsp_catalog_load();

    /* Step 1: Get LSP count and needed size (sizing pass).
     * lsp_enum_protocols now returns count even when buffer is NULL. */
    lsp_count = lsp_enum_protocols( protocols, NULL, &lsp_needed, FALSE );
    if (lsp_count < 0) lsp_count = 0;

    /* Step 2: Get builtin needed size.
     * WSAEnumProtocolsW with NULL buffer returns SOCKET_ERROR but
     * correctly sets *builtin_needed to the actual needed size. */
    builtin_needed = 0;
    WSAEnumProtocolsW( protocols, NULL, &builtin_needed );

    total_needed = lsp_needed + builtin_needed;
    TRACE( "lsp_count=%d lsp_needed=%lu builtin_needed=%lu total=%lu orig=%lu\n",
           lsp_count, lsp_needed, builtin_needed, total_needed, orig_len );

    /* Step 3: sizing query or buffer too small */
    if (!info || orig_len < total_needed)
    {
        *len = total_needed;
        *err = WSAENOBUFS;
        TRACE( "-> WSAENOBUFS, need %lu bytes\n", total_needed );
        TlsSetValue(tls_wsc_reentrant, NULL);
        return -1;
    }

    /* Step 4: fill LSP providers at the start of the buffer */
    if (lsp_count > 0)
    {
        DWORD lsp_actual = orig_len;
        DWORD remaining;
        int lsp_filled = lsp_enum_protocols( protocols, info, &lsp_actual, FALSE );
        if (lsp_filled < 0) lsp_filled = 0;

        /* Step 5: fill builtin providers after LSP entries.
         * WSAEnumProtocolsW does NOT update *size on success, so compute
         * bytes used from builtin_count. */
        remaining = orig_len - lsp_actual;
        builtin_count = WSAEnumProtocolsW(
            protocols, (WSAPROTOCOL_INFOW *)((BYTE *)info + lsp_actual), &remaining );
        if (builtin_count >= 0)
        {
            *len = lsp_actual + builtin_count * sizeof(WSAPROTOCOL_INFOW);
            TRACE( "-> %d LSP + %d builtin = %d total, %lu bytes\n",
                   lsp_filled, builtin_count, lsp_filled + builtin_count, *len );
            TlsSetValue(tls_wsc_reentrant, NULL);
            return lsp_filled + builtin_count;
        }
        /* Builtin failed – return just LSP providers */
        *len = lsp_actual;
        TRACE( "-> %d LSP only (builtin failed), %lu bytes\n", lsp_filled, *len );
        TlsSetValue(tls_wsc_reentrant, NULL);
        return lsp_filled;
    }

    /* Step 6: no LSP providers – return only builtins */
    builtin_needed = orig_len;
    builtin_count = WSAEnumProtocolsW( protocols, info, &builtin_needed );
    if (builtin_count < 0) { *len = builtin_needed; *err = WSAENOBUFS; TlsSetValue(tls_wsc_reentrant, NULL); return -1; }
    *len = builtin_count * sizeof(WSAPROTOCOL_INFOW);
    TRACE( "-> %d builtin only, %lu bytes\n", builtin_count, *len );
    TlsSetValue(tls_wsc_reentrant, NULL);
    return builtin_count;
}