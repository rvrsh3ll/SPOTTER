/*
 * shareacl.c - Beacon Object File for enumerating SMB share ACLs.
 *
 * Usage (Cobalt Strike):
 *   beacon> shareacl <host>
 *   beacon> shareacl \\server\share
 *   beacon> shareacl --computers
 *   beacon> shareacl --computers --ldaps
 *
 * The "--computers" mode queries Active Directory for enabled computer objects
 * and enumerates shares/ACLs on each discovered host.  The other modes target a
 * single host or share.  The BOF runs under the current Beacon token/context and
 * emits one JSON object per share, prefixed with "[shareacl] ", suitable for
 * ingestion into SPOTTER's
 * Flowsint graph database via scripts/shareacl_normalizer.py.
 *
 * In addition to the Beacon console output, every "[shareacl] " line is written
 * to a local file ("shareacl_results.txt") in the Beacon's current working
 * directory on the target host.  The file is byte-for-byte consumable by
 * scripts/shareacl_normalizer.py with no further editing.
 *
 * Safe-use constraints:
 *   - Authorized red-team / penetration-test engagements only.
 *   - Performs read-only enumeration; no share or ACL modifications are made.
 *   - All queries run under the current Windows user context of the Beacon.
 *   - Drops a results file on the target's disk; clean it up post-engagement.
 */

#include <windows.h>
#include <lm.h>
#include <aclapi.h>
#include <sddl.h>
#include <winldap.h>
#include <dsgetdc.h>
#include "beacon.h"

/* ── Dynamic Function Resolution (DFR) declarations ─────────────────────── */

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrcmpiW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrcmpiA(LPCSTR, LPCSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcpynW(LPWSTR, LPCWSTR, int);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentDirectoryA(DWORD, LPSTR);

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR, LPCWSTR, GUID*, LPCWSTR, ULONG, PDOMAIN_CONTROLLER_INFOW*);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetShareEnum(LPWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetNamedSecurityInfoW(LPWSTR, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID*, PSID*, PACL*, PACL*, PSECURITY_DESCRIPTOR*);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$ConvertSidToStringSidW(PSID, LPWSTR*);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$GetAclInformation(PACL, LPVOID, DWORD, ACL_INFORMATION_CLASS);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$GetAce(PACL, DWORD, LPVOID*);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);

/* ── LDAP Dynamic Function Resolution ────────────────────────────────────── */

DECLSPEC_IMPORT LDAP*   WINAPI WLDAP32$ldap_init(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG   WINAPI WLDAP32$ldap_set_option(LDAP*, int, void*);
DECLSPEC_IMPORT ULONG   WINAPI WLDAP32$ldap_bind_s(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG   WINAPI WLDAP32$ldap_search_s(LDAP*, PWSTR, ULONG, PWSTR, PZPWSTR, LONG, PLDAPMessage*);
DECLSPEC_IMPORT ULONG   WINAPI WLDAP32$ldap_count_entries(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR*  WINAPI WLDAP32$ldap_get_values(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG   WINAPI WLDAP32$ldap_value_free(PWSTR*);
DECLSPEC_IMPORT ULONG   WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG   WINAPI WLDAP32$ldap_unbind(LDAP*);

/* ── Growable UTF-8 string buffer (backed by the process heap) ──────────── */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} StringBuilder;

static BOOL sb_init(StringBuilder *sb, size_t initial)
{
    sb->data = (char *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, initial);
    if (!sb->data) return FALSE;
    sb->len = 0;
    sb->cap = initial;
    sb->data[0] = '\0';
    return TRUE;
}

static BOOL sb_grow(StringBuilder *sb, size_t need)
{
    if (sb->len + need + 1 <= sb->cap) return TRUE;
    size_t new_cap = sb->cap * 2;
    while (new_cap < sb->len + need + 1) new_cap *= 2;
    char *nd = (char *)KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sb->data, new_cap);
    if (!nd) return FALSE;
    sb->data = nd;
    sb->cap = new_cap;
    return TRUE;
}

static void sb_append(StringBuilder *sb, const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    if (!sb_grow(sb, n)) return;
    for (size_t i = 0; i < n; i++) sb->data[sb->len++] = s[i];
    sb->data[sb->len] = '\0';
}

static void sb_append_ch(StringBuilder *sb, char c)
{
    char s[2] = { c, '\0' };
    sb_append(sb, s);
}

static void sb_append_int(StringBuilder *sb, long long v)
{
    char buf[32];
    int i = 0;
    if (v < 0) {
        sb_append(sb, "-");
        v = -v;
    }
    if (v == 0) {
        sb_append(sb, "0");
        return;
    }
    while (v > 0) {
        buf[i++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (i--) sb_append_ch(sb, buf[i]);
}

static void sb_append_hex(StringBuilder *sb, DWORD v)
{
    char *hex = "0123456789ABCDEF";
    sb_append(sb, "0x");
    for (int i = 28; i >= 0; i -= 4) {
        char s[2] = { hex[(v >> i) & 0xF], '\0' };
        sb_append(sb, s);
    }
}

/* Append a wide string as a JSON string literal (UTF-8, escaped). */
static void sb_append_wstr_json(StringBuilder *sb, LPCWSTR wstr)
{
    if (!wstr) {
        sb_append(sb, "null");
        return;
    }

    int cb = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (cb <= 0) {
        sb_append(sb, "\"\"");
        return;
    }

    char *tmp = (char *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
    if (!tmp) {
        sb_append(sb, "\"\"");
        return;
    }
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, tmp, cb, NULL, NULL);

    sb_append(sb, "\"");
    for (int i = 0; tmp[i]; i++) {
        unsigned char c = (unsigned char)tmp[i];
        if (c == '\\' || c == '"') {
            sb_append_ch(sb, '\\');
            sb_append_ch(sb, (char)c);
        } else if (c == '\b') sb_append(sb, "\\b");
        else if (c == '\f') sb_append(sb, "\\f");
        else if (c == '\n') sb_append(sb, "\\n");
        else if (c == '\r') sb_append(sb, "\\r");
        else if (c == '\t') sb_append(sb, "\\t");
        else if (c < 0x20) {
            /* Control characters are uncommon in account names; emit Unicode escape. */
            char *hex = "0123456789ABCDEF";
            sb_append(sb, "\\u00");
            sb_append_ch(sb, hex[c >> 4]);
            sb_append_ch(sb, hex[c & 0xF]);
        } else {
            sb_append_ch(sb, (char)c);
        }
    }
    sb_append(sb, "\"");

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, tmp);
}

/* ── Local results file (written to the Beacon's current working directory) ─ */

#define SHAREACL_OUTFILE "shareacl_results.txt"

/* Fresh file per invocation; INVALID_HANDLE_VALUE means "console only". */
static HANDLE g_out_file = INVALID_HANDLE_VALUE;
static BOOL g_verbose = TRUE;

static void vlog(const char *msg)
{
    if (g_verbose && msg) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", (char *)msg);
    }
}

static void file_open(void)
{
    g_out_file = KERNEL32$CreateFileA(
        SHAREACL_OUTFILE,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (g_out_file == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
            "shareacl: could not open output file %s (rc=%lu); console output only",
            SHAREACL_OUTFILE, KERNEL32$GetLastError());
        return;
    }

    char cwd[MAX_PATH] = { 0 };
    DWORD n = KERNEL32$GetCurrentDirectoryA(MAX_PATH, cwd);
    if (n > 0 && n < MAX_PATH) {
        BeaconPrintf(CALLBACK_OUTPUT, "shareacl: writing results to %s\\%s", cwd, SHAREACL_OUTFILE);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "shareacl: writing results to %s (cwd)", SHAREACL_OUTFILE);
    }
}

static void file_close(void)
{
    if (g_out_file != INVALID_HANDLE_VALUE) {
        KERNEL32$CloseHandle(g_out_file);
        g_out_file = INVALID_HANDLE_VALUE;
    }
}

/* Append one CRLF-terminated line to the results file (no-op if not open). */
static void file_write_line(const char *s)
{
    if (g_out_file == INVALID_HANDLE_VALUE || !s) return;

    DWORD len = 0;
    while (s[len]) len++;

    DWORD written = 0;
    if (len) KERNEL32$WriteFile(g_out_file, s, len, &written, NULL);
    KERNEL32$WriteFile(g_out_file, "\r\n", 2, &written, NULL);
}

/* Emit a JSON result line to both the Beacon console and the results file. */
static void emit(const char *s)
{
    BeaconPrintf(CALLBACK_OUTPUT, "%s", (char *)s);
    file_write_line(s);
}

/* Write a JSON line to the results file only (console gets icacls output). */
static void emit_file(const char *s)
{
    file_write_line(s);
}

static BOOL is_space_char(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static BOOL next_token(const char *input, size_t *offset, char *token, size_t token_cap)
{
    size_t i = *offset;
    while (input[i] && is_space_char(input[i])) i++;
    if (!input[i]) {
        *offset = i;
        return FALSE;
    }

    size_t t = 0;
    while (input[i] && !is_space_char(input[i])) {
        if (t + 1 < token_cap) token[t++] = input[i];
        i++;
    }

    token[t] = 0;
    *offset = i;
    return TRUE;
}

/* ── Utility helpers ─────────────────────────────────────────────────────── */

static size_t wstr_len(LPCWSTR s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static void wstr_cpy(LPWSTR dst, LPCWSTR src, size_t max_chars)
{
    size_t i = 0;
    while (i + 1 < max_chars && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
}

/* Map ACCESS_MASK to human-readable share right names. */
static void mask_to_rights(StringBuilder *sb, DWORD mask)
{
    BOOL first = TRUE;

    sb_append(sb, "[");

    if ((mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS || (mask & GENERIC_ALL) == GENERIC_ALL) {
        sb_append(sb, "\"FULL\"");
        first = FALSE;
    } else {
        if ((mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE || (mask & GENERIC_WRITE) == GENERIC_WRITE) {
            if (!first) sb_append(sb, ",");
            sb_append(sb, "\"WRITE\"");
            first = FALSE;
        }
        if ((mask & FILE_GENERIC_READ) == FILE_GENERIC_READ || (mask & GENERIC_READ) == GENERIC_READ) {
            if (!first) sb_append(sb, ",");
            sb_append(sb, "\"READ\"");
            first = FALSE;
        }
        if ((mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE || (mask & GENERIC_EXECUTE) == GENERIC_EXECUTE) {
            if (!first) sb_append(sb, ",");
            sb_append(sb, "\"EXECUTE\"");
            first = FALSE;
        }
    }

    sb_append(sb, "]");
}

static void effective_access(StringBuilder *sb, DWORD mask, BYTE ace_type)
{
    if (ace_type == ACCESS_DENIED_ACE_TYPE) {
        sb_append(sb, "\"DENY\"");
        return;
    }
    if ((mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS || (mask & GENERIC_ALL) == GENERIC_ALL) {
        sb_append(sb, "\"FULL\"");
    } else if ((mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE || (mask & GENERIC_WRITE) == GENERIC_WRITE) {
        sb_append(sb, "\"WRITE\"");
    } else if ((mask & FILE_GENERIC_READ) == FILE_GENERIC_READ || (mask & GENERIC_READ) == GENERIC_READ) {
        sb_append(sb, "\"READ\"");
    } else if ((mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE || (mask & GENERIC_EXECUTE) == GENERIC_EXECUTE) {
        sb_append(sb, "\"EXECUTE\"");
    } else {
        sb_append(sb, "\"CUSTOM\"");
    }
}

/* Convert an ACCESS_MASK + ACE type to an icacls-style permission string. */
static void mask_to_icacls(char *buf, size_t cap, DWORD mask, BYTE ace_type)
{
    size_t pos = 0;

    #define ICACLS_APPEND(s) do { const char *_p = (s); while (*_p && pos + 1 < cap) buf[pos++] = *_p++; } while(0)

    if (ace_type == ACCESS_DENIED_ACE_TYPE) {
        ICACLS_APPEND("(DENY)");
    }

    if ((mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS || (mask & GENERIC_ALL) == GENERIC_ALL) {
        ICACLS_APPEND("(F)"); buf[pos] = '\0'; return;
    }

    BOOL has_r = ((mask & FILE_GENERIC_READ) == FILE_GENERIC_READ) || ((mask & GENERIC_READ) == GENERIC_READ);
    BOOL has_w = ((mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE) || ((mask & GENERIC_WRITE) == GENERIC_WRITE);
    BOOL has_x = ((mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE) || ((mask & GENERIC_EXECUTE) == GENERIC_EXECUTE);
    BOOL has_d = (mask & DELETE) == DELETE;

    if (has_r && has_w && has_x && has_d) {
        ICACLS_APPEND("(M)"); buf[pos] = '\0'; return;
    }
    if (has_r && has_x && !has_w) {
        ICACLS_APPEND("(RX)"); buf[pos] = '\0'; return;
    }
    if (has_r && !has_w && !has_x) {
        ICACLS_APPEND("(R)"); buf[pos] = '\0'; return;
    }
    if (has_w && !has_r) {
        ICACLS_APPEND("(W)"); buf[pos] = '\0'; return;
    }

    ICACLS_APPEND("(");
    {
        BOOL first = TRUE;

        #define ICACLS_BIT(bit, abbr) \
            if (mask & (bit)) { \
                if (!first && pos + 1 < cap) buf[pos++] = ','; \
                ICACLS_APPEND(abbr); \
                first = FALSE; \
            }

        ICACLS_BIT(DELETE, "DE")
        ICACLS_BIT(READ_CONTROL, "RC")
        ICACLS_BIT(WRITE_DAC, "WDAC")
        ICACLS_BIT(WRITE_OWNER, "WO")
        ICACLS_BIT(SYNCHRONIZE, "S")
        ICACLS_BIT(FILE_READ_DATA, "RD")
        ICACLS_BIT(FILE_WRITE_DATA, "WD")
        ICACLS_BIT(FILE_APPEND_DATA, "AD")
        ICACLS_BIT(FILE_READ_EA, "REA")
        ICACLS_BIT(FILE_WRITE_EA, "WEA")
        ICACLS_BIT(FILE_EXECUTE, "X")
        ICACLS_BIT(FILE_DELETE_CHILD, "DC")
        ICACLS_BIT(FILE_READ_ATTRIBUTES, "RA")
        ICACLS_BIT(FILE_WRITE_ATTRIBUTES, "WA")

        #undef ICACLS_BIT
    }
    ICACLS_APPEND(")");
    buf[pos] = '\0';

    #undef ICACLS_APPEND
}

static void trustee_type(StringBuilder *sb, SID_NAME_USE use)
{
    switch (use) {
        case SidTypeUser:           sb_append(sb, "\"User\""); break;
        case SidTypeGroup:          sb_append(sb, "\"Group\""); break;
        case SidTypeDomain:         sb_append(sb, "\"Domain\""); break;
        case SidTypeAlias:          sb_append(sb, "\"Alias\""); break;
        case SidTypeWellKnownGroup: sb_append(sb, "\"WellKnownGroup\""); break;
        case SidTypeDeletedAccount: sb_append(sb, "\"DeletedAccount\""); break;
        case SidTypeInvalid:        sb_append(sb, "\"Invalid\""); break;
        case SidTypeUnknown:        sb_append(sb, "\"Unknown\""); break;
        case SidTypeComputer:       sb_append(sb, "\"Computer\""); break;
        case SidTypeLabel:          sb_append(sb, "\"Label\""); break;
        default:                    sb_append(sb, "\"Other\""); break;
    }
}

static void share_type_name(StringBuilder *sb, DWORD type)
{
    switch (type & ~STYPE_SPECIAL) {
        case STYPE_DISKTREE:  sb_append(sb, "\"DISK\""); break;
        case STYPE_PRINTQ:    sb_append(sb, "\"PRINT\""); break;
        case STYPE_DEVICE:    sb_append(sb, "\"DEVICE\""); break;
        case STYPE_IPC:       sb_append(sb, "\"IPC\""); break;
        case STYPE_TEMPORARY: sb_append(sb, "\"TEMPORARY\""); break;
        default:              sb_append(sb, "\"UNKNOWN\""); break;
    }
}

/* ── ACL enumeration ─────────────────────────────────────────────────────── */

static char *build_acl_json(LPCWSTR host, PACL acl)
{
    StringBuilder sb;
    if (!sb_init(&sb, 4096)) return NULL;

    sb_append(&sb, "[");

    ACL_SIZE_INFORMATION info;
    if (!ADVAPI32$GetAclInformation(acl, &info, sizeof(info), AclSizeInformation)) {
        sb_append(&sb, "]");
        return sb.data;
    }

    for (DWORD i = 0; i < info.AceCount; i++) {
        LPVOID ace = NULL;
        if (!ADVAPI32$GetAce(acl, i, &ace)) continue;

        ACE_HEADER *hdr = (ACE_HEADER *)ace;
        ACCESS_MASK mask = 0;
        PSID sid = NULL;

        if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *a = (ACCESS_ALLOWED_ACE *)ace;
            mask = a->Mask;
            sid = &a->SidStart;
        } else if (hdr->AceType == ACCESS_DENIED_ACE_TYPE) {
            ACCESS_DENIED_ACE *d = (ACCESS_DENIED_ACE *)ace;
            mask = d->Mask;
            sid = &d->SidStart;
        } else {
            /* Skip object ACEs and audit ACEs for this version. */
            continue;
        }

        WCHAR name[256] = { 0 }, domain[256] = { 0 };
        DWORD name_len = 255, domain_len = 255;
        SID_NAME_USE use = SidTypeUnknown;
        BOOL resolved = ADVAPI32$LookupAccountSidW(host, sid, name, &name_len, domain, &domain_len, &use);

        WCHAR *sid_str = NULL;
        ADVAPI32$ConvertSidToStringSidW(sid, &sid_str);

        if (i > 0) sb_append(&sb, ",");
        sb_append(&sb, "{");

        sb_append(&sb, "\"trustee_sid\":");
        sb_append_wstr_json(&sb, sid_str);
        sb_append(&sb, ",\"trustee_name\":");
        sb_append_wstr_json(&sb, resolved ? name : NULL);
        sb_append(&sb, ",\"trustee_domain\":");
        sb_append_wstr_json(&sb, resolved ? domain : NULL);
        sb_append(&sb, ",\"trustee_type\":");
        trustee_type(&sb, resolved ? use : SidTypeUnknown);
        sb_append(&sb, ",\"access_mask\":");
        sb_append_int(&sb, (long long)mask);
        sb_append(&sb, ",\"access_mask_hex\":\"");
        sb_append_hex(&sb, mask);
        sb_append(&sb, "\"");
        sb_append(&sb, ",\"ace_type\":");
        sb_append(&sb, hdr->AceType == ACCESS_DENIED_ACE_TYPE ? "\"ACCESS_DENIED\"" : "\"ACCESS_ALLOWED\"");
        sb_append(&sb, ",\"rights\":");
        mask_to_rights(&sb, mask);
        sb_append(&sb, ",\"effective_access\":");
        effective_access(&sb, mask, hdr->AceType);

        sb_append(&sb, "}");

        if (sid_str) KERNEL32$LocalFree(sid_str);
    }

    sb_append(&sb, "]");
    return sb.data;
}

/* ── Single share processing ─────────────────────────────────────────────── */

static void build_unc(LPWSTR unc, size_t max, LPCWSTR host, LPCWSTR share)
{
    size_t p = 0;
    unc[p++] = '\\';
    if (p < max) unc[p++] = '\\';

    size_t i = 0;
    while (host[i] && p + 1 < max) unc[p++] = host[i++];

    if (p + 1 < max) unc[p++] = '\\';

    i = 0;
    while (share[i] && p + 1 < max) unc[p++] = share[i++];
    unc[p] = 0;
}

static BOOL is_hidden_share(LPCWSTR share)
{
    size_t n = wstr_len(share);
    return n > 0 && share[n - 1] == L'$';
}

/* Print icacls-style ACL output to the Beacon console. */
static void print_icacls_acl(LPCWSTR unc, LPCWSTR host, PACL dacl, DWORD rc)
{
    BeaconPrintf(CALLBACK_OUTPUT, "%ls", unc);

    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Access is denied. (error %lu)", rc);
        BeaconPrintf(CALLBACK_OUTPUT, "");
        return;
    }

    if (!dacl) {
        BeaconPrintf(CALLBACK_OUTPUT, "    (no DACL - full access granted to all)");
        BeaconPrintf(CALLBACK_OUTPUT, "");
        return;
    }

    ACL_SIZE_INFORMATION aclInfo;
    if (!ADVAPI32$GetAclInformation(dacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
        BeaconPrintf(CALLBACK_OUTPUT, "");
        return;
    }

    for (DWORD i = 0; i < aclInfo.AceCount; i++) {
        LPVOID ace = NULL;
        if (!ADVAPI32$GetAce(dacl, i, &ace)) continue;

        ACE_HEADER *hdr = (ACE_HEADER *)ace;
        ACCESS_MASK mask = 0;
        PSID sid = NULL;

        if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *a = (ACCESS_ALLOWED_ACE *)ace;
            mask = a->Mask;
            sid = &a->SidStart;
        } else if (hdr->AceType == ACCESS_DENIED_ACE_TYPE) {
            ACCESS_DENIED_ACE *d = (ACCESS_DENIED_ACE *)ace;
            mask = d->Mask;
            sid = &d->SidStart;
        } else {
            continue;
        }

        WCHAR name[256] = { 0 }, domain[256] = { 0 };
        DWORD name_len = 255, domain_len = 255;
        SID_NAME_USE use = SidTypeUnknown;
        BOOL resolved = ADVAPI32$LookupAccountSidW(host, sid, name, &name_len, domain, &domain_len, &use);

        WCHAR *sid_str = NULL;
        ADVAPI32$ConvertSidToStringSidW(sid, &sid_str);

        char perm[128] = { 0 };
        mask_to_icacls(perm, sizeof(perm), mask, hdr->AceType);

        if (resolved && domain[0] && name[0]) {
            BeaconPrintf(CALLBACK_OUTPUT, "    %ls\\%ls:%s", domain, name, perm);
        } else if (resolved && name[0]) {
            BeaconPrintf(CALLBACK_OUTPUT, "    %ls:%s", name, perm);
        } else if (sid_str) {
            BeaconPrintf(CALLBACK_OUTPUT, "    %ls:%s", sid_str, perm);
        }

        if (sid_str) KERNEL32$LocalFree(sid_str);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "");
}

static void process_share(LPCWSTR host, LPCWSTR share_name, DWORD share_type)
{
    WCHAR unc[512] = { 0 };
    build_unc(unc, 512, host, share_name);

    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    DWORD rc = ADVAPI32$GetNamedSecurityInfoW(
        unc,
        SE_LMSHARE,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        &dacl,
        NULL,
        &sd
    );

    StringBuilder sb;
    if (!sb_init(&sb, 8192)) return;

    sb_append(&sb, "[shareacl] {");
    sb_append(&sb, "\"host\":");
    sb_append_wstr_json(&sb, host);
    sb_append(&sb, ",\"share_name\":");
    sb_append_wstr_json(&sb, share_name);
    sb_append(&sb, ",\"unc_path\":");
    sb_append_wstr_json(&sb, unc);
    sb_append(&sb, ",\"is_hidden\":");
    sb_append(&sb, is_hidden_share(share_name) ? "true" : "false");
    sb_append(&sb, ",\"share_type\":");
    share_type_name(&sb, share_type);
    sb_append(&sb, ",\"source\":\"shareacl_bof\"");
    sb_append(&sb, ",\"error_code\":");
    if (rc == ERROR_SUCCESS) {
        sb_append(&sb, "null");
    } else {
        sb_append_int(&sb, (long long)rc);
    }

    sb_append(&sb, ",\"acls\":");
    if (rc == ERROR_SUCCESS && dacl) {
        char *acl_json = build_acl_json(host, dacl);
        if (acl_json) {
            sb_append(&sb, acl_json);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, acl_json);
        } else {
            sb_append(&sb, "[]");
        }
    } else {
        sb_append(&sb, "[]");
    }

    sb_append(&sb, "}");

    emit_file(sb.data);
    print_icacls_acl(unc, host, dacl, rc);

    if (sd) KERNEL32$LocalFree((HLOCAL)sd);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, sb.data);
}

/* ── Structured event lines (mirrored to console + results file) ─────────── */

static void emit_event_start(LPCWSTR host, LPCWSTR target)
{
    StringBuilder sb;
    if (!sb_init(&sb, 256)) return;
    sb_append(&sb, "[shareacl] {\"source\":\"shareacl_bof\",\"host\":");
    sb_append_wstr_json(&sb, host);
    sb_append(&sb, ",\"target\":");
    sb_append_wstr_json(&sb, target);
    sb_append(&sb, ",\"event\":\"start\"}");
    emit_file(sb.data);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, sb.data);
}

static void emit_event_done(LPCWSTR host, DWORD count)
{
    StringBuilder sb;
    if (!sb_init(&sb, 256)) return;
    sb_append(&sb, "[shareacl] {\"source\":\"shareacl_bof\",\"host\":");
    sb_append_wstr_json(&sb, host);
    sb_append(&sb, ",\"event\":\"done\",\"count\":");
    sb_append_int(&sb, (long long)count);
    sb_append(&sb, "}");
    emit_file(sb.data);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, sb.data);
}

static void emit_event_ad_found(DWORD count)
{
    StringBuilder sb;
    if (!sb_init(&sb, 128)) return;
    sb_append(&sb, "[shareacl] {\"source\":\"shareacl_bof\",\"event\":\"ad_computers_found\",\"count\":");
    sb_append_int(&sb, (long long)count);
    sb_append(&sb, "}");
    emit_file(sb.data);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, sb.data);
}

static void emit_event_ad_done(DWORD count, DWORD processed)
{
    StringBuilder sb;
    if (!sb_init(&sb, 128)) return;
    sb_append(&sb, "[shareacl] {\"source\":\"shareacl_bof\",\"event\":\"ad_computers_done\",\"count\":");
    sb_append_int(&sb, (long long)count);
    sb_append(&sb, ",\"processed\":");
    sb_append_int(&sb, (long long)processed);
    sb_append(&sb, "}");
    emit_file(sb.data);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, sb.data);
}

/* ── Host enumeration ────────────────────────────────────────────────────── */

static void process_host(LPCWSTR host)
{
    if (g_verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "shareacl: enumerating shares on host %ls", host);
    }

    LPBYTE buf = NULL;
    DWORD read = 0, total = 0, resume = 0;
    DWORD rc = NETAPI32$NetShareEnum((LPWSTR)host, 1, &buf, MAX_PREFERRED_LENGTH, &read, &total, &resume);

    if (rc != NERR_Success && rc != ERROR_MORE_DATA) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: NetShareEnum failed on host (rc=%lu)", rc);
        return;
    }

    if (g_verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "shareacl: host %ls returned %lu/%lu shares", host, read, total);
        if (rc == ERROR_MORE_DATA) {
            vlog("shareacl: additional share data available; continuing with current response set");
        }
    }

    emit_event_start(host, host);

    SHARE_INFO_1 *shares = (SHARE_INFO_1 *)buf;
    for (DWORD i = 0; i < read; i++) {
        process_share(host, shares[i].shi1_netname, shares[i].shi1_type);
    }

    emit_event_done(host, read);
    BeaconPrintf(CALLBACK_OUTPUT, "Successfully processed %lu shares on %ls.", read, host);

    if (buf) NETAPI32$NetApiBufferFree(buf);
}

/* ── Active Directory computer enumeration ──────────────────────────────── */

static void enumerate_ad_computers(BOOL use_ldaps)
{
    if (use_ldaps) {
        vlog("shareacl: --computers mode selected; using LDAPS transport");
    } else {
        vlog("shareacl: --computers mode selected; using LDAP transport");
    }
    vlog("shareacl: discovering domain controller");

    PDOMAIN_CONTROLLER_INFOW dcInfo = NULL;
    DWORD ds = NETAPI32$DsGetDcNameW(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &dcInfo);
    if (ds != ERROR_SUCCESS || !dcInfo || !dcInfo->DomainControllerName) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: DsGetDcNameW failed (ds=%lu)", ds);
        if (dcInfo) NETAPI32$NetApiBufferFree(dcInfo);
        return;
    }

    /* DomainControllerName is returned as a UNC (\\DC01); strip the leading backslashes for ldap_init. */
    LPCWSTR dc_name = dcInfo->DomainControllerName;
    if (dc_name[0] == L'\\' && dc_name[1] == L'\\') dc_name += 2;

    if (g_verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "shareacl: LDAP target domain controller is %ls", dc_name);
    }

    ULONG ldap_port = use_ldaps ? 636 : LDAP_PORT;
    LDAP *ld = WLDAP32$ldap_init((PWSTR)dc_name, ldap_port);
    NETAPI32$NetApiBufferFree(dcInfo);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: ldap_init failed");
        return;
    }

    if (use_ldaps) {
        ULONG ssl_rc = WLDAP32$ldap_set_option(ld, LDAP_OPT_SSL, LDAP_OPT_ON);
        if (ssl_rc != LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "shareacl: failed to enable LDAPS (rc=%lu)", ssl_rc);
            WLDAP32$ldap_unbind(ld);
            return;
        }
    }

    ULONG version = LDAP_VERSION3;
    WLDAP32$ldap_set_option(ld, LDAP_VERSION, &version);
    vlog("shareacl: LDAP session initialized; binding with current Beacon token");

    ULONG rc = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: ldap_bind_s failed (rc=%lu)", rc);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    /* Discover the default naming context for the domain. */
    PWSTR root_attrs[] = { L"defaultNamingContext", L"namingContexts", NULL };
    LDAPMessage *root_res = NULL;
    vlog("shareacl: querying rootDSE for domain naming context");
    rc = WLDAP32$ldap_search_s(ld, NULL, LDAP_SCOPE_BASE, L"(objectClass=*)", root_attrs, 0, &root_res);
    if (rc != LDAP_SUCCESS || !root_res) {
        /* Some LDAP servers reject explicit attribute lists on RootDSE queries. */
        if (root_res) {
            WLDAP32$ldap_msgfree(root_res);
            root_res = NULL;
        }
        rc = WLDAP32$ldap_search_s(ld, NULL, LDAP_SCOPE_BASE, L"(objectClass=*)", NULL, 0, &root_res);
    }
    if (rc != LDAP_SUCCESS || !root_res) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: rootDSE search failed (rc=%lu)", rc);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    WCHAR base_dn[512] = { 0 };
    LDAPMessage *root_entry = WLDAP32$ldap_first_entry(ld, root_res);
    if (root_entry) {
        PWSTR *vals = WLDAP32$ldap_get_values(ld, root_entry, L"defaultNamingContext");
        if (vals && vals[0]) {
            wstr_cpy(base_dn, vals[0], 512);
        }
        WLDAP32$ldap_value_free(vals);

        if (!base_dn[0]) {
            vals = WLDAP32$ldap_get_values(ld, root_entry, L"namingContexts");
            if (vals) {
                for (DWORD i = 0; vals[i]; i++) {
                    LPCWSTR candidate = vals[i];
                    if (!candidate || !candidate[0]) continue;
                    BOOL has_dc = FALSE;
                    for (DWORD j = 0; candidate[j] && candidate[j + 2]; j++) {
                        if ((candidate[j] == L'D' || candidate[j] == L'd') &&
                            (candidate[j + 1] == L'C' || candidate[j + 1] == L'c') &&
                            candidate[j + 2] == L'=') {
                            has_dc = TRUE;
                            break;
                        }
                    }
                    if (has_dc) {
                        wstr_cpy(base_dn, candidate, 512);
                        break;
                    }
                }

                if (!base_dn[0] && vals[0]) {
                    wstr_cpy(base_dn, vals[0], 512);
                }
            }
            WLDAP32$ldap_value_free(vals);
        }
    }
    WLDAP32$ldap_msgfree(root_res);

    if (!base_dn[0]) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: unable to determine domain naming context");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    if (g_verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "shareacl: searching enabled computer objects under %ls", base_dn);
    }

    /* Search for enabled computer objects. Filter excludes disabled accounts. */
    PWSTR comp_attrs[] = { L"dNSHostName", L"name", NULL };
    LDAPMessage *comp_res = NULL;
    rc = WLDAP32$ldap_search_s(
        ld,
        base_dn,
        LDAP_SCOPE_SUBTREE,
        L"(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        comp_attrs,
        0,
        &comp_res
    );

    if (rc != LDAP_SUCCESS || !comp_res) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: computer search failed (rc=%lu)", rc);
        WLDAP32$ldap_unbind(ld);
        return;
    }

    ULONG count = WLDAP32$ldap_count_entries(ld, comp_res);
    emit_event_ad_found(count);
    if (g_verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "shareacl: LDAP returned %lu enabled computer objects", count);
    }

    ULONG processed = 0;
    for (LDAPMessage *entry = WLDAP32$ldap_first_entry(ld, comp_res); entry; entry = WLDAP32$ldap_next_entry(ld, entry)) {
        WCHAR host[256] = { 0 };
        PWSTR *dns_vals = WLDAP32$ldap_get_values(ld, entry, L"dNSHostName");
        if (dns_vals && dns_vals[0]) {
            wstr_cpy(host, dns_vals[0], 256);
        }
        WLDAP32$ldap_value_free(dns_vals);

        if (!host[0]) {
            PWSTR *name_vals = WLDAP32$ldap_get_values(ld, entry, L"name");
            if (name_vals && name_vals[0]) {
                wstr_cpy(host, name_vals[0], 256);
            }
            WLDAP32$ldap_value_free(name_vals);
        }

        if (host[0]) {
            if (g_verbose) {
                BeaconPrintf(CALLBACK_OUTPUT, "shareacl: processing AD computer %ls", host);
            }
            process_host(host);
            processed++;
        }
    }

    WLDAP32$ldap_msgfree(comp_res);
    WLDAP32$ldap_unbind(ld);

    emit_event_ad_done(count, processed);
    BeaconPrintf(CALLBACK_OUTPUT, "Completed processing %lu/%lu AD computers.", processed, count);
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

void go(char *args, int alen)
{
    datap parser;
    BeaconDataParse(&parser, args, alen);

    char *cmdline_ansi = BeaconDataExtract(&parser, NULL);
    if (!cmdline_ansi || !*cmdline_ansi) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: usage: shareacl <host> | shareacl \\\\server\\share | shareacl --computers [--ldaps]");
        return;
    }

    BOOL computers_mode = FALSE;
    BOOL use_ldaps = FALSE;
    BOOL saw_target = FALSE;
    char target_ansi[512] = { 0 };
    size_t offset = 0;
    char token[512] = { 0 };

    while (next_token(cmdline_ansi, &offset, token, sizeof(token))) {
        if (KERNEL32$lstrcmpiA(token, "--computers") == 0) {
            computers_mode = TRUE;
            continue;
        }
        if (KERNEL32$lstrcmpiA(token, "--ldaps") == 0 || KERNEL32$lstrcmpiA(token, "--secure-ldap") == 0) {
            use_ldaps = TRUE;
            continue;
        }
        if (token[0] == '-') {
            BeaconPrintf(CALLBACK_ERROR, "shareacl: unknown option: %s", token);
            return;
        }
        if (saw_target) {
            BeaconPrintf(CALLBACK_ERROR, "shareacl: too many targets; use one host/UNC or --computers");
            return;
        }

        size_t i = 0;
        while (token[i] && i + 1 < sizeof(target_ansi)) {
            target_ansi[i] = token[i];
            i++;
        }
        if (token[i]) {
            BeaconPrintf(CALLBACK_ERROR, "shareacl: target is too long");
            return;
        }
        target_ansi[i] = 0;
        saw_target = TRUE;
    }

    if (computers_mode && saw_target) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: use either <target> or --computers, not both");
        return;
    }
    if (use_ldaps && !computers_mode) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: --ldaps is only valid with --computers mode");
        return;
    }
    if (!computers_mode && !saw_target) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: usage: shareacl <host> | shareacl \\\\server\\share | shareacl --computers [--ldaps]");
        return;
    }

    vlog("shareacl: starting enumeration");

    /* Open the local results file in the Beacon's current working directory.
     * Failure is non-fatal: enumeration still streams to the console. */
    file_open();

    /* Active Directory computer sweep mode. */
    if (computers_mode) {
        enumerate_ad_computers(use_ldaps);
        vlog("shareacl: enumeration complete");
        file_close();
        return;
    }

    int wlen = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, target_ansi, -1, NULL, 0);
    if (wlen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: failed to convert target to wide char");
        file_close();
        return;
    }

    LPWSTR target = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, wlen * sizeof(WCHAR));
    if (!target) {
        BeaconPrintf(CALLBACK_ERROR, "shareacl: memory allocation failed");
        file_close();
        return;
    }

    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, target_ansi, -1, target, wlen);

    /* Strip a trailing backslash if present. */
    size_t tl = wstr_len(target);
    if (tl > 0 && target[tl - 1] == L'\\') target[tl - 1] = 0;

    if (wstr_len(target) >= 2 && target[0] == L'\\' && target[1] == L'\\') {
        /* UNC path: \\server\share[\...] */
        LPCWSTR rest = target + 2;
        /* Find next backslash to isolate server. */
        size_t i = 0;
        while (rest[i] && rest[i] != L'\\') i++;

        if (rest[i] != L'\\' || rest[i + 1] == 0) {
            BeaconPrintf(CALLBACK_ERROR, "shareacl: invalid UNC path (need \\\\server\\share)");
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, target);
            file_close();
            return;
        }

        WCHAR server[256] = { 0 };
        wstr_cpy(server, rest, i < 255 ? i + 1 : 255);

        LPCWSTR share_start = rest + i + 1;
        WCHAR share[256] = { 0 };
        size_t j = 0;
        while (share_start[j] && share_start[j] != L'\\' && j < 255) {
            share[j] = share_start[j];
            j++;
        }
        share[j] = 0;

        if (g_verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "shareacl: UNC target resolved to host=%ls share=%ls", server, share);
        }

        emit_event_start(server, target);
        process_share(server, share, STYPE_DISKTREE);
        emit_event_done(server, 1);
    } else {
        if (g_verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "shareacl: host target resolved to %ls", target);
        }
        process_host(target);
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, target);
    vlog("shareacl: enumeration complete");
    file_close();
}
