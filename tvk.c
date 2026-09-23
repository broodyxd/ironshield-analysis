#include "tvk.h"
#include <bcrypt.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include <winioctl.h>

_Static_assert(sizeof(((tvk_arguments *)0)->path_rule) == 0x408, "path ABI");
_Static_assert(sizeof(((tvk_arguments *)0)->read_memory) == 0x30, "read ABI");
_Static_assert(offsetof(tvk_arguments, open_process.result) == 0x18, "open ABI");
_Static_assert(offsetof(tvk_arguments, query_memory.result) == 0x18, "query ABI");
_Static_assert(offsetof(tvk_arguments, events.remaining) == 0x20, "event ABI");

#define IOCTL_TVK_POLICY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_PATH_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_PROCESS_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x841, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_SYMBOL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x842, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_OPEN_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x843, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_MODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_OPEN_KERNEL_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x844, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_CLOSE_HANDLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x845, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_QUERY_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x846, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x847, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_IMAGE_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x848, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_CI_OPTIONS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x849, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84A, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_CREATE_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84B, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84C, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

static const tvk_command_info commands[] = {
    { 1, IOCTL_TVK_POLICY, 0x218, 0x8, "policy" },
    { 2, IOCTL_TVK_PATH_RULE, 0x618, 0x408, "path-rule" },
    { 3, IOCTL_TVK_PROCESS_RULE, 0x228, 0x18, "process-rule" },
    { 4, IOCTL_TVK_SYMBOL, 0x220, 0x10, "symbol" },
    { 5, IOCTL_TVK_OPEN_PROCESS, 0x230, 0x20, "open-process" },
    { 6, IOCTL_TVK_MODE, 0x214, 0x4, "mode" },
    { 7, IOCTL_TVK_OPEN_KERNEL_PROCESS, 0x230, 0x20, "open-kernel-process" },
    { 8, IOCTL_TVK_CLOSE_HANDLE, 0x220, 0x10, "close-handle" },
    { 9, IOCTL_TVK_QUERY_MEMORY, 0x230, 0x20, "query-memory" },
    { 10, IOCTL_TVK_READ_MEMORY, 0x240, 0x30, "read-memory" },
    { 11, IOCTL_TVK_IMAGE_BASE, 0x228, 0x18, "image-base" },
    { 12, IOCTL_TVK_CI_OPTIONS, 0x218, 0x8, "ci-options" },
    { 13, IOCTL_TVK_CALLBACKS, 0x230, 0x20, "callbacks" },
    { 14, IOCTL_TVK_CREATE_EVENT, 0x220, 0x10, "create-event" },
    { 15, IOCTL_TVK_EVENTS, 0x238, 0x28, "events" }
};

static BOOL fail(DWORD error) {
    SetLastError(error);
    return FALSE;
}

static uint32_t get32(const void *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static void put32(void *p, uint32_t v) { memcpy(p, &v, 4); }
static void put64(void *p, uint64_t v) { memcpy(p, &v, 8); }

static uint32_t rol(uint32_t x, unsigned n) {
    n &= 31;
    return (x << n) | (x >> ((32 - n) & 31));
}

static void keys(uint32_t schedule[193]) {
    static const uint8_t key[32] = {
        0x04,0x8d,0xfa,0x76,0xde,0x54,0xe5,0xbb,0xd7,0xb7,0x5a,0x8f,0x76,0xcf,0x4c,0x49,
        0xe3,0x03,0x97,0x42,0x57,0x5a,0xc6,0x06,0xb2,0x4d,0x5f,0xfe,0xd1,0x45,0x9a,0x4e
    };
    static const uint32_t delta[8] = {
        0xc3efe9db,0x44626b02,0x79e27c8a,0x78df30ec,
        0x715ea49e,0xc785da0a,0xe04ef22a,0xe5c40957
    };
    static const unsigned rotations[6] = {1,3,6,11,13,17};
    uint32_t t[8];
    unsigned i, j, p;

    for (i = 0; i < 8; ++i)
        t[i] = get32(key + i * 4);
    
    for (i = 0; i < 32; ++i) {
        for (j = 0; j < 6; ++j) {
            p = (6 * i + j) & 7;
            t[p] = rol(t[p] + rol(delta[i & 7], i + j), rotations[j]);
            schedule[6 * i + j] = t[p];
        }
    }
    
    schedule[192] = 32;
}

static void encrypt(uint8_t *data, DWORD size, const uint8_t iv[16], const uint32_t schedule[193]) {
    uint32_t x[4], y[4];
    uint8_t chain[16];
    DWORD offset;
    unsigned i, r;
    memcpy(chain, iv, 16);

    for (offset = 0; offset < size; offset += 16) {
        for (i = 0; i < 4; ++i)
            x[i] = get32(data + offset + 4*i) ^ get32(chain + 4*i);
        
        for (r = 0; r < 32; ++r) {
            const uint32_t *k = schedule + r*6;
            y[0] = rol((x[0] ^ k[0]) + (x[1] ^ k[1]), 9);
            y[1] = rol((x[1] ^ k[2]) + (x[2] ^ k[3]), 27);
            y[2] = rol((x[2] ^ k[4]) + (x[3] ^ k[5]), 29);
            y[3] = x[0];
            memcpy(x, y, sizeof(x));
        }

        for (i = 0; i < 4; ++i)
            put32(data + offset + 4*i, x[i]);
        
        memcpy(chain, data + offset, 16);
    }
}

static BOOL authenticate(uint8_t *packet, DWORD size, uint32_t schedule[193]) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (NT_SUCCESS(status))
        status = BCryptCreateHash(algorithm, &hash, NULL, 0, (PUCHAR)schedule, 0x304, 0);
    if (NT_SUCCESS(status))
        status = BCryptHashData(hash, packet, size, 0);
    if (NT_SUCCESS(status))
        status = BCryptFinishHash(hash, packet + 0x40, 32, 0);
    if (hash)
        BCryptDestroyHash(hash);
    if (algorithm)
        BCryptCloseAlgorithmProvider(algorithm, 0);

    return NT_SUCCESS(status) ? TRUE : fail(ERROR_ENCRYPTION_FAILED);
}

const tvk_command_info *tvk_info(unsigned command) {
    return command >= 1 && command <= 15 ? commands + command - 1 : NULL;
}

uint64_t tvk_symbol_hash(const char *name) {
    // FNV-1a 64
    uint64_t hash = UINT64_C(0xcbf29ce484222325);

    if (!name)
        return 0;
    
    while (*name)
        hash = (hash ^ (uint8_t)*name++) * UINT64_C(0x100000001b3);
    
    return hash;
}

BOOL tvk_encode(unsigned command, const tvk_arguments *arguments,
                uint64_t session, uint64_t sequence, const uint8_t iv[16],
                BOOL legacy, void *packet, DWORD capacity, DWORD *written) {
    static const uint8_t legacy_iv[16] = {
        0x35,0xd7,0x74,0x7b,0xa1,0xda,0xe8,0xa3,
        0x9a,0x6f,0x27,0xde,0x1f,0x20,0x1f,0x77
    };
    const tvk_command_info *info = tvk_info(command);
    uint8_t *frame = packet, *body;
    uint32_t schedule[193];
    DWORD padded, total;
    BOOL ok;

    if (written)
        *written = 0;

    if (!info || !arguments || !packet || !written ||
        (legacy && command != TVK_MODE) ||
        (!legacy && (!session || !sequence || !iv)))
        return fail(ERROR_INVALID_PARAMETER);
    
    padded = (info->request_size + 15) & ~15u;
    total = padded + (legacy ? 0 : TVK_FRAME_HEADER);
    
    if (capacity < total)
        return fail(ERROR_INSUFFICIENT_BUFFER);
    
    memset(frame, 0, total);
    body = frame + (legacy ? 0 : TVK_FRAME_HEADER);
    put32(body, info->request_size);
    put32(body + 12, command);
    memcpy(body + 16, arguments, info->argument_size);
    keys(schedule);
    encrypt(body, padded, legacy ? legacy_iv : iv, schedule);

    if (!legacy) {
        put32(frame, 'SKVT');
        put32(frame + 4, 1);
        put32(frame + 8, TVK_FRAME_HEADER);
        put32(frame + 12, command);
        put32(frame + 16, 3); // both mandatory flag bits
        put64(frame + 24, sequence);
        put64(frame + 32, session);
        put32(frame + 40, info->request_size);
        put32(frame + 44, padded);
        memcpy(frame + 48, iv, 16);
    }

    ok = legacy || authenticate(frame, total, schedule);
    SecureZeroMemory(schedule, sizeof(schedule));
    if (!ok) {
        SecureZeroMemory(frame, total);
        return FALSE;
    }

    *written = total;
    return TRUE;
}

BOOL tvk_open(tvk_client *client, const WCHAR *device_name) {
    WCHAR path[260];
    size_t n;

    if (!client)
        return fail(ERROR_INVALID_PARAMETER);

    memset(client, 0, sizeof(*client));
    client->device = INVALID_HANDLE_VALUE;
    InitializeSRWLock(&client->lock);

    if (!device_name)
        device_name = L"tvk";

    n = wcslen(device_name);

    if (n > 250)
        return fail(ERROR_FILENAME_EXCED_RANGE);

    if (wcsncmp(device_name, L"\\\\.\\", 4) == 0)
        memcpy(path, device_name, (n + 1) * sizeof(WCHAR));
    else {
        memcpy(path, L"\\\\.\\", 4 * sizeof(WCHAR));
        memcpy(path + 4, device_name, (n + 1) * sizeof(WCHAR));
    }

    do {
        if (!NT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)&client->session, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
            return fail(ERROR_GEN_FAILURE);
    } while (!client->session);

    client->device = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (client->device == INVALID_HANDLE_VALUE)
        return FALSE;

    client->owner = GetCurrentProcessId();
    return TRUE;
}

void tvk_close(tvk_client *client) {
    if (!client)
        return;
    
    AcquireSRWLockExclusive(&client->lock);

    if (client->device && client->device != INVALID_HANDLE_VALUE)
        CloseHandle(client->device);
    
    client->device = INVALID_HANDLE_VALUE;
    client->owner = 0;
    client->session = client->sequence = 0;

    ReleaseSRWLockExclusive(&client->lock);
}

BOOL tvk_send(tvk_client *client, unsigned command,
              const tvk_arguments *arguments, BOOL legacy,
              void *output, DWORD output_size, DWORD *returned) {
    const tvk_command_info *info = tvk_info(command);
    tvk_arguments args;
    uint8_t packet[TVK_MAX_PACKET], iv[16];
    DWORD size = 0, bytes = 0, error = ERROR_SUCCESS;
    BOOL ok = FALSE;

    if (returned)
        *returned = 0;

    if (!client || !info || !arguments || (output_size && !output))
        return fail(ERROR_INVALID_PARAMETER);
    
    AcquireSRWLockExclusive(&client->lock);

    if (!client->device || client->device == INVALID_HANDLE_VALUE || client->owner != GetCurrentProcessId()) {
        error = ERROR_INVALID_HANDLE;
        goto done;
    }

    if (client->sequence == UINT64_MAX || (legacy && client->sequence)) {
        error = ERROR_INVALID_STATE;
        goto done;
    }

    args = *arguments;

    switch (command) {
    case TVK_OPEN_PROCESS: case TVK_OPEN_KERNEL_PROCESS: args.open_process.caller = client->owner; break;
    case TVK_CLOSE_HANDLE: args.close_handle.caller = client->owner; break;
    case TVK_QUERY_MEMORY: args.query_memory.caller = client->owner; break;
    case TVK_READ_MEMORY: args.read_memory.caller = client->owner; break;
    case TVK_IMAGE_BASE: args.image_base.caller = client->owner; break;
    case TVK_CALLBACKS: args.callbacks.caller = client->owner; break;
    case TVK_CREATE_EVENT: args.create_event.caller = client->owner; break;
    case TVK_EVENTS: args.events.caller = client->owner; break;
    default: break;
    }

    if (!NT_SUCCESS(BCryptGenRandom(NULL, iv, sizeof(iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        error = ERROR_GEN_FAILURE;
        goto done;
    }

    if (!tvk_encode(command, &args, client->session, client->sequence + 1, iv, legacy, packet, sizeof(packet), &size)) {
        error = GetLastError();
        goto done;
    }

    // The driver consumes sequence state before dispatch, including failures
    ++client->sequence;
    ok = DeviceIoControl(client->device, info->ioctl, packet, size, output, output_size, &bytes, NULL);
    error = ok ? ERROR_SUCCESS : GetLastError();

    if (returned)
        *returned = bytes;

done:
    SecureZeroMemory(packet, sizeof(packet));
    ReleaseSRWLockExclusive(&client->lock);

    if (!ok)
        SetLastError(error);
    
    return ok;
}
