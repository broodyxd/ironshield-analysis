#include "tvk.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

static void print_usage(void) {
    printf("Ironshield Driver Client\n");
    printf("========================\n\n");
    printf("Commands:\n");
    printf("  info              - Show all IOCTL command info\n");
    printf("  hash <name>       - Compute FNV-1a symbol hash\n");
    printf("  connect [device]  - Connect to driver (default: tvk)\n");
    printf("  policy <cat> <v>  - Set policy value\n");
    printf("  mode <value>      - Set mode (legacy packet)\n");
    printf("  symbol <name> <offset> - Register symbol offset\n");
    printf("  cioptions         - Query g_CiOptions\n");
    printf("  callbacks         - Enumerate object callbacks\n");
    printf("  open <pid> <access> - Open process handle\n");
    printf("  imgbase <pid>     - Get process image base\n");
    printf("  read <pid> <addr> <size> - Read process memory\n");
    printf("  query <pid> <addr> - Query memory information\n");
    printf("  close <handle>    - Close kernel handle\n");
    printf("  quit              - Exit\n\n");
}

static void cmd_info(void) {
    printf("\n%-4s %-22s %-10s %-10s %-10s\n", "ID", "Name", "IOCTL", "ReqSize", "ArgSize");
    printf("---- ---------------------- ---------- ---------- ----------\n");
    for (unsigned i = 1; i <= 15; ++i) {
        const tvk_command_info *info = tvk_info(i);
        if (info) {
            printf("%-4u %-22s 0x%08X 0x%-8X 0x%-8X\n",
                   info->id, info->name, info->ioctl,
                   info->request_size, info->argument_size);
        }
    }
    printf("\n");
}

static void cmd_hash(const char *name) {
    uint64_t h = tvk_symbol_hash(name);
    printf("FNV-1a(\"%s\") = 0x%016" PRIX64 "\n", name, h);
}

static tvk_client client = {0};
static BOOL connected = FALSE;

static void cmd_connect(const char *device) {
    if (connected) {
        printf("Already connected. Closing previous connection.\n");
        tvk_close(&client);
        connected = FALSE;
    }

    WCHAR wdevice[260] = {0};
    if (device) {
        MultiByteToWideChar(CP_UTF8, 0, device, -1, wdevice, 260);
    }

    if (tvk_open(&client, device ? wdevice : NULL)) {
        connected = TRUE;
        printf("Connected to \\\\.\\%ls (session=0x%016" PRIX64 ", pid=%lu)\n",
               device ? wdevice : L"tvk", client.session, client.owner);
    } else {
        printf("Failed to connect: error %lu\n", GetLastError());
    }
}

static BOOL ensure_connected(void) {
    if (!connected) {
        printf("Not connected. Use 'connect' first.\n");
        return FALSE;
    }
    return TRUE;
}

static void cmd_policy(uint32_t category, uint32_t value) {
    if (!ensure_connected()) return;

    tvk_arguments args = {0};
    args.policy.category = category;
    args.policy.value = value;

    DWORD returned = 0;
    if (tvk_send(&client, TVK_POLICY, &args, FALSE, NULL, 0, &returned)) {
        printf("Policy set: category=%u, value=0x%X\n", category, value);
    } else {
        printf("Failed: error %lu\n", GetLastError());
    }
}

static void cmd_mode(uint32_t value) {
    if (!ensure_connected()) return;

    tvk_arguments args = {0};
    args.mode.value = value;

    DWORD returned = 0;
    if (tvk_send(&client, TVK_MODE, &args, TRUE, NULL, 0, &returned)) {
        printf("Mode set: value=0x%X\n", value);
    } else {
        printf("Failed: error %lu\n", GetLastError());
    }
}

static void cmd_symbol(const char *name, uint64_t offset) {
    if (!ensure_connected()) return;

    tvk_arguments args = {0};
    args.symbol.hash = tvk_symbol_hash(name);
    args.symbol.offset = offset;

    DWORD returned = 0;
    if (tvk_send(&client, TVK_SYMBOL, &args, FALSE, NULL, 0, &returned)) {
        printf("Symbol registered: \"%s\" (hash=0x%016" PRIX64 ") -> offset=0x%" PRIX64 "\n",
               name, args.symbol.hash, offset);
    } else {
        printf("Failed: error %lu\n", GetLastError());
    }
}

static void cmd_cioptions(void) {
    if (!ensure_connected()) return;

    uint32_t ci_value = 0;
    tvk_arguments args = {0};
    args.ci_options.result = &ci_value;

    uint8_t output[256] = {0};
    DWORD returned = 0;
    if (tvk_send(&client, TVK_CI_OPTIONS, &args, FALSE, output, sizeof(output), &returned)) {
        printf("g_CiOptions = 0x%X\n", ci_value);
    } else {
        printf("Failed: error %lu\n", GetLastError());
    }
}

static void cmd_callbacks(void) {
    if (!ensure_connected()) return;

    uint64_t count = 0;
    uint8_t records[TVK_CALLBACK_SIZE * TVK_MAX_RECORDS] = {0};
    tvk_arguments args = {0};
    args.callbacks.records = records;
    args.callbacks.capacity_bytes = sizeof(records);
    args.callbacks.count = &count;

    uint8_t output[4096] = {0};
    DWORD returned = 0;
    if (tvk_send(&client, TVK_CALLBACKS, &args, FALSE, output, sizeof(output), &returned)) {
        printf("Callbacks enumerated: %" PRIu64 " entries\n", count);
    } else {
        printf("Failed: error %lu\n", GetLastError());
    }
}

static void cmd_open_process(uint64_t pid, uint32_t access) {
    if (!ensure_connected()) return;

    uint64_t handle = 0;
    tvk_arguments args = {0};
    args.open_process.process = pid;
    args.open_process.access = access;
    args.open_process.result = &handle;

    uint8_t output[256] = {0};
    DWORD returned = 0;
    if (tvk_send(&client, TVK_OPEN_PROCESS, &args, FALSE, output, sizeof(output), &returned)) {
        printf("Process opened: pid=%" PRIu64 ", handle=0x%" PRIX64 "\n", pid, handle);
    } else {
        printf("Failed: error %lu\n", GetLastError());
    }
}

static void cmd_image_base(uint64_t pid) {
    if (!ensure_connected()) return;

    uint64_t base = 0;
    tvk_arguments args = {0};
    args.image_base.process = pid;
    args.image_base.result = &base;

    uint8_t output[256] = {0};
    DWORD returned = 0;
    if (tvk_send(&client, TVK_IMAGE_BASE, &args, FALSE, output, sizeof(output), &returned)) {
        printf("Image base: pid=%" PRIu64 ", base=0x%016" PRIX64 "\n", pid, base);
    } else {
        printf("Failed: error %lu\n", GetLastError());
    }
}

static void cmd_read_memory(uint64_t handle, uint64_t address, uint64_t size) {
    if (!ensure_connected()) return;

    if (size > 0x10000) {
        printf("Size capped at 64KB for safety.\n");
        size = 0x10000;
    }

    void *buffer = calloc(1, (size_t)size);
    if (!buffer) {
        printf("Allocation failed.\n");
        return;
    }

    tvk_arguments args = {0};
    args.read_memory.handle = handle;
    args.read_memory.address = address;
    args.read_memory.minimum_size = size;
    args.read_memory.buffer = buffer;
    args.read_memory.capacity = size;

    uint8_t output[4096] = {0};
    DWORD returned = 0;
    if (tvk_send(&client, TVK_READ_MEMORY, &args, FALSE, output, sizeof(output), &returned)) {
        printf("Memory at 0x%016" PRIX64 " (%" PRIu64 " bytes):\n", address, size);
        uint8_t *p = (uint8_t *)buffer;
        for (uint64_t i = 0; i < size; i += 16) {
            printf("  %016" PRIX64 ": ", address + i);
            for (uint64_t j = 0; j < 16 && (i + j) < size; ++j)
                printf("%02X ", p[i + j]);
            printf(" | ");
            for (uint64_t j = 0; j < 16 && (i + j) < size; ++j) {
                uint8_t c = p[i + j];
                printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
            }
            printf("\n");
        }
    } else {
        printf("Failed: error %lu\n", GetLastError());
    }

    free(buffer);
}

static void cmd_query_memory(uint64_t handle, uint64_t address) {
    if (!ensure_connected()) return;

    MEMORY_BASIC_INFORMATION mbi = {0};
    tvk_arguments args = {0};
    args.query_memory.handle = handle;
    args.query_memory.address = address;
    args.query_memory.result = &mbi;

    uint8_t output[4096] = {0};
    DWORD returned = 0;
    if (tvk_send(&client, TVK_QUERY_MEMORY, &args, FALSE, output, sizeof(output), &returned)) {
        printf("Memory info at 0x%016" PRIX64 ":\n", address);
        printf("  BaseAddress:       0x%p\n", mbi.BaseAddress);
        printf("  AllocationBase:    0x%p\n", mbi.AllocationBase);
        printf("  RegionSize:        0x%zX\n", mbi.RegionSize);
        printf("  State:             0x%lX\n", mbi.State);
        printf("  Protect:           0x%lX\n", mbi.Protect);
        printf("  Type:              0x%lX\n", mbi.Type);
    } else {
        printf("Failed: error %lu\n", GetLastError());
    }
}

static void cmd_close_handle(uint64_t handle) {
    if (!ensure_connected()) return;

    tvk_arguments args = {0};
    args.close_handle.handle = handle;

    DWORD returned = 0;
    if (tvk_send(&client, TVK_CLOSE_HANDLE, &args, FALSE, NULL, 0, &returned)) {
        printf("Handle 0x%" PRIX64 " closed.\n", handle);
    } else {
        printf("Failed: error %lu\n", GetLastError());
    }
}

int main(int argc, char *argv[]) {
    char line[1024];
    char cmd[64];

    print_usage();

    while (1) {
        printf("tvk> ");
        if (!fgets(line, sizeof(line), stdin))
            break;

        line[strcspn(line, "\n")] = 0;
        if (line[0] == 0)
            continue;

        if (sscanf(line, "%63s", cmd) != 1)
            continue;

        if (_stricmp(cmd, "quit") == 0 || _stricmp(cmd, "exit") == 0) {
            break;
        } else if (_stricmp(cmd, "help") == 0) {
            print_usage();
        } else if (_stricmp(cmd, "info") == 0) {
            cmd_info();
        } else if (_stricmp(cmd, "hash") == 0) {
            char name[256];
            if (sscanf(line, "%*s %255s", name) == 1)
                cmd_hash(name);
            else
                printf("Usage: hash <name>\n");
        } else if (_stricmp(cmd, "connect") == 0) {
            char device[256];
            if (sscanf(line, "%*s %255s", device) == 1)
                cmd_connect(device);
            else
                cmd_connect(NULL);
        } else if (_stricmp(cmd, "policy") == 0) {
            unsigned cat, val;
            if (sscanf(line, "%*s %u %u", &cat, &val) == 2)
                cmd_policy(cat, val);
            else
                printf("Usage: policy <category> <value>\n");
        } else if (_stricmp(cmd, "mode") == 0) {
            unsigned val;
            if (sscanf(line, "%*s %u", &val) == 1)
                cmd_mode(val);
            else
                printf("Usage: mode <value>\n");
        } else if (_stricmp(cmd, "symbol") == 0) {
            char name[256];
            uint64_t offset;
            if (sscanf(line, "%*s %255s %" SCNx64, name, &offset) == 2)
                cmd_symbol(name, offset);
            else
                printf("Usage: symbol <name> <offset_hex>\n");
        } else if (_stricmp(cmd, "cioptions") == 0) {
            cmd_cioptions();
        } else if (_stricmp(cmd, "callbacks") == 0) {
            cmd_callbacks();
        } else if (_stricmp(cmd, "open") == 0) {
            uint64_t pid;
            unsigned access;
            if (sscanf(line, "%*s %" SCNu64 " %x", &pid, &access) == 2)
                cmd_open_process(pid, access);
            else
                printf("Usage: open <pid> <access_hex>\n");
        } else if (_stricmp(cmd, "imgbase") == 0) {
            uint64_t pid;
            if (sscanf(line, "%*s %" SCNu64, &pid) == 1)
                cmd_image_base(pid);
            else
                printf("Usage: imgbase <pid>\n");
        } else if (_stricmp(cmd, "read") == 0) {
            uint64_t handle, addr, size;
            if (sscanf(line, "%*s %" SCNx64 " %" SCNx64 " %" SCNx64, &handle, &addr, &size) == 3)
                cmd_read_memory(handle, addr, size);
            else
                printf("Usage: read <handle_hex> <address_hex> <size_hex>\n");
        } else if (_stricmp(cmd, "query") == 0) {
            uint64_t handle, addr;
            if (sscanf(line, "%*s %" SCNx64 " %" SCNx64, &handle, &addr) == 2)
                cmd_query_memory(handle, addr);
            else
                printf("Usage: query <handle_hex> <address_hex>\n");
        } else if (_stricmp(cmd, "close") == 0) {
            uint64_t handle;
            if (sscanf(line, "%*s %" SCNx64, &handle) == 1)
                cmd_close_handle(handle);
            else
                printf("Usage: close <handle_hex>\n");
        } else {
            printf("Unknown command: %s (type 'help')\n", cmd);
        }
    }

    if (connected)
        tvk_close(&client);

    printf("Bye.\n");
    return 0;
}
