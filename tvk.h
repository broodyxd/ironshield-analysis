#ifndef TVK_H
#define TVK_H

#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <stdint.h>

enum tvk_command {
    TVK_POLICY = 1,
    TVK_PATH_RULE,
    TVK_PROCESS_RULE,
    TVK_SYMBOL,
    TVK_OPEN_PROCESS,
    TVK_MODE,
    TVK_OPEN_KERNEL_PROCESS,
    TVK_CLOSE_HANDLE,
    TVK_QUERY_MEMORY,
    TVK_READ_MEMORY,
    TVK_IMAGE_BASE,
    TVK_CI_OPTIONS,
    TVK_CALLBACKS,
    TVK_CREATE_EVENT,
    TVK_EVENTS
};

typedef struct {
    uint32_t id;
    uint32_t ioctl;
    uint32_t request_size;
    uint32_t argument_size;
    const char *name;
} tvk_command_info;

typedef union {
    struct {
        uint32_t category;
        uint32_t value;
    } policy;

    struct {
        uint32_t category;
        uint32_t tag;
        WCHAR path[512];
    } path_rule;

    struct {
        uint32_t category;
        uint32_t reserved;
        uint64_t process;
        uint64_t peer;
    } process_rule;

    struct {
        uint64_t hash;
        uint64_t offset;
    } symbol;
    
    struct {
        uint64_t process;
        uint64_t caller;
        uint32_t access;
        uint32_t reserved;
        uint64_t *result;
    } open_process;

    struct {
        uint32_t value;
    } mode;

    struct {
        uint64_t handle;
        uint64_t caller;
    } close_handle;

    struct {
        uint64_t handle;
        uint64_t caller;
        uint64_t address;
        MEMORY_BASIC_INFORMATION *result;
    } query_memory;

    // Driver checks capacity >= minimum_size, then copies capacity bytes
    struct {
        uint64_t handle;
        uint64_t caller;
        uint64_t address;
        uint64_t minimum_size;
        void *buffer;
        uint64_t capacity;
    } read_memory;
    
    struct {
        uint64_t process;
        uint64_t caller;
        uint64_t *result;
    } image_base;

    struct {
        uint32_t *result;
    } ci_options;

    struct {
        uint64_t caller;
        void *records;
        uint64_t capacity_bytes;
        uint64_t *count;
    } callbacks;

    struct {
        uint64_t caller;
        uint32_t kind;
        uint32_t reserved;
    } create_event;

    struct {
        uint64_t caller;
        void *records;
        uint64_t capacity_bytes;
        uint64_t *count;
        uint64_t *remaining;
    } events;
} tvk_arguments;

enum {
    TVK_FRAME_HEADER = 0x60,
    TVK_MAX_PACKET = 0x680,
    TVK_CALLBACK_SIZE = 0x818,
    TVK_EVENT_SIZE = 0x30,
    TVK_MAX_RECORDS = 64
};

typedef struct {
    HANDLE device;
    uint64_t session;
    uint64_t sequence;
    DWORD owner;
    SRWLOCK lock;
} tvk_client;

const tvk_command_info *tvk_info(unsigned command);
uint64_t tvk_symbol_hash(const char *name);

BOOL tvk_encode(unsigned command, const tvk_arguments *arguments,
                uint64_t session, uint64_t sequence, const uint8_t iv[16],
                BOOL legacy, void *packet, DWORD capacity, DWORD *written);
BOOL tvk_open(tvk_client *client, const WCHAR *device_name);
void tvk_close(tvk_client *client);
BOOL tvk_send(tvk_client *client, unsigned command,
              const tvk_arguments *arguments, BOOL legacy,
              void *output, DWORD output_size, DWORD *returned);

#endif
