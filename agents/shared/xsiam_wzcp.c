#include "shared.h"
#include "xsiam_wzcp.h"

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#endif

static uint64_t wzcp_seq = 0;
static char wzcp_agent_uuid[64] = "";

static uint32_t get_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t get_be64(const unsigned char *p)
{
    uint64_t hi = get_be32(p);
    uint64_t lo = get_be32(p + 4);
    return (hi << 32) | lo;
}

static void put_be16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)v;
}

static void put_be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static void put_be64(unsigned char *p, uint64_t v)
{
    put_be32(p, (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)v);
}

static int send_all(int sock, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;

    while (sent < len) {
        int rc = send(sock, p + sent, (int)(len - sent), 0);
        if (rc <= 0) {
            return -1;
        }
        sent += (size_t)rc;
    }

    return 0;
}

static int recv_all(int sock, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t got = 0;

    while (got < len) {
        int rc = recv(sock, p + got, (int)(len - got), 0);
        if (rc <= 0) {
            return -1;
        }
        got += (size_t)rc;
    }

    return 0;
}

int xsiam_wzcp_enabled(void)
{
    const char *value = getenv("XSIAM_GATEWAY_PROTOCOL");
    return value && strcmp(value, "wzcp") == 0;
}

static int read_uuid_file(char *out, size_t out_size)
{
    FILE *fp;
    char *nl;

    fp = fopen("xsiam-agent.uuid", "r");
    if (!fp) {
        return -1;
    }

    if (!fgets(out, (int)out_size, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    nl = strchr(out, '\n');
    if (nl) {
        *nl = '\0';
    }
    nl = strchr(out, '\r');
    if (nl) {
        *nl = '\0';
    }
    return out[0] ? 0 : -1;
}

static void write_uuid_file(const char *uuid)
{
    FILE *fp = fopen("xsiam-agent.uuid", "w");
    if (fp) {
        fprintf(fp, "%s\n", uuid);
        fclose(fp);
    }
}

static void generate_uuid(char *out, size_t out_size)
{
#ifdef WIN32
    unsigned char b[16];

    srand((unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)&b);
    for (size_t i = 0; i < sizeof(b); i++) {
        b[i] = rand() & 0xff;
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    snprintf(out, out_size,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
#else
    int fd;
    unsigned char b[16];

    fd = open("/proc/sys/kernel/random/uuid", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, out, out_size - 1);
        close(fd);
        if (n > 0) {
            out[n] = '\0';
            if (strchr(out, '\n')) {
                *strchr(out, '\n') = '\0';
            }
            return;
        }
    }

    srand((unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)&fd);
    for (size_t i = 0; i < sizeof(b); i++) {
        b[i] = rand() & 0xff;
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    snprintf(out, out_size,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
#endif
}

const char *xsiam_wzcp_agent_uuid(void)
{
    const char *env_uuid;

    if (wzcp_agent_uuid[0]) {
        return wzcp_agent_uuid;
    }

    env_uuid = getenv("XSIAM_AGENT_UUID");
    if (env_uuid && env_uuid[0]) {
        snprintf(wzcp_agent_uuid, sizeof(wzcp_agent_uuid), "%s", env_uuid);
        return wzcp_agent_uuid;
    }

    if (read_uuid_file(wzcp_agent_uuid, sizeof(wzcp_agent_uuid)) == 0) {
        return wzcp_agent_uuid;
    }

    generate_uuid(wzcp_agent_uuid, sizeof(wzcp_agent_uuid));
    write_uuid_file(wzcp_agent_uuid);
    return wzcp_agent_uuid;
}

const char *xsiam_wzcp_host_type(void)
{
    const char *env_type = getenv("XSIAM_HOST_TYPE");

    if (env_type && (strcmp(env_type, "server") == 0 || strcmp(env_type, "pc") == 0)) {
        return env_type;
    }

#ifdef WIN32
    OSVERSIONINFOEXA osvi;

    memset(&osvi, 0, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (GetVersionExA((OSVERSIONINFOA *)&osvi) &&
        osvi.wProductType != VER_NT_WORKSTATION) {
        return "server";
    }
#endif

    return "pc";
}

int xsiam_wzcp_collect_mac_addresses(char *out, size_t out_size)
{
    size_t used = 0;

    if (!out || out_size == 0) {
        return -1;
    }
    out[0] = '\0';

#ifdef WIN32
    IP_ADAPTER_INFO *info = NULL;
    IP_ADAPTER_INFO *cur;
    ULONG len = 0;
    DWORD rc;

    rc = GetAdaptersInfo(NULL, &len);
    if (rc != ERROR_BUFFER_OVERFLOW || len == 0) {
        return 0;
    }

    info = (IP_ADAPTER_INFO *)malloc(len);
    if (!info) {
        return -1;
    }

    rc = GetAdaptersInfo(info, &len);
    if (rc != NO_ERROR) {
        free(info);
        return 0;
    }

    for (cur = info; cur; cur = cur->Next) {
        char mac[18];

        if (cur->AddressLength != 6) {
            continue;
        }

        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 cur->Address[0], cur->Address[1], cur->Address[2],
                 cur->Address[3], cur->Address[4], cur->Address[5]);

        if (used > 0) {
            if (used + 1 >= out_size) {
                break;
            }
            out[used++] = ',';
            out[used] = '\0';
        }

        if (used + strlen(mac) >= out_size) {
            break;
        }
        memcpy(out + used, mac, strlen(mac) + 1);
        used += strlen(mac);
    }

    free(info);
#else
    (void)used;
#endif

    return 0;
}

uint64_t xsiam_wzcp_now_ms(void)
{
#ifdef WIN32
    FILETIME ft;
    ULARGE_INTEGER uli;
    GetSystemTimeAsFileTime(&ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return (uli.QuadPart / 10000ULL) - 11644473600000ULL;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((uint64_t)tv.tv_sec * 1000ULL) + ((uint64_t)tv.tv_usec / 1000ULL);
#endif
}

uint64_t xsiam_wzcp_next_seq(void)
{
    return ++wzcp_seq;
}

void xsiam_wzcp_pack_header(unsigned char *out, const struct xsiam_wzcp_header *h)
{
    put_be32(out, h->magic);
    out[4] = h->version;
    out[5] = h->header_len;
    out[6] = h->flags;
    out[7] = h->msg_type;
    put_be32(out + 8, h->agent_id);
    put_be64(out + 12, h->seq);
    put_be64(out + 20, h->timestamp_ms);
    put_be32(out + 28, h->body_len);
}

int xsiam_wzcp_unpack_header(const unsigned char *in, struct xsiam_wzcp_header *h)
{
    h->magic = get_be32(in);
    h->version = in[4];
    h->header_len = in[5];
    h->flags = in[6];
    h->msg_type = in[7];
    h->agent_id = get_be32(in + 8);
    h->seq = get_be64(in + 12);
    h->timestamp_ms = get_be64(in + 20);
    h->body_len = get_be32(in + 28);

    if (h->magic != XSIAM_WZCP_MAGIC ||
        h->version != XSIAM_WZCP_VERSION ||
        h->header_len != XSIAM_WZCP_HEADER_SIZE ||
        h->body_len > XSIAM_WZCP_MAX_FRAME) {
        return -1;
    }

    return 0;
}

int xsiam_wzcp_send_frame(int sock, uint8_t msg_type, uint32_t agent_id,
                          uint64_t seq, const void *body, uint32_t body_len)
{
    unsigned char hdr[XSIAM_WZCP_HEADER_SIZE];
    unsigned char len_buf[4];
    struct xsiam_wzcp_header h;
    uint32_t frame_len = XSIAM_WZCP_HEADER_SIZE + body_len;

    if (body_len > XSIAM_WZCP_MAX_FRAME) {
        return -1;
    }

    h.magic = XSIAM_WZCP_MAGIC;
    h.version = XSIAM_WZCP_VERSION;
    h.header_len = XSIAM_WZCP_HEADER_SIZE;
    h.flags = 0;
    h.msg_type = msg_type;
    h.agent_id = agent_id;
    h.seq = seq;
    h.timestamp_ms = xsiam_wzcp_now_ms();
    h.body_len = body_len;

    put_be32(len_buf, frame_len);
    xsiam_wzcp_pack_header(hdr, &h);

    if (send_all(sock, len_buf, sizeof(len_buf)) < 0 ||
        send_all(sock, hdr, sizeof(hdr)) < 0) {
        return -1;
    }

    if (body_len > 0 && send_all(sock, body, body_len) < 0) {
        return -1;
    }

    return 0;
}

int xsiam_wzcp_recv_frame(int sock, struct xsiam_wzcp_header *h,
                          unsigned char *body, uint32_t body_cap)
{
    unsigned char len_buf[4];
    unsigned char hdr[XSIAM_WZCP_HEADER_SIZE];
    uint32_t frame_len;

    if (recv_all(sock, len_buf, sizeof(len_buf)) < 0) {
        return -1;
    }

    frame_len = get_be32(len_buf);
    if (frame_len < XSIAM_WZCP_HEADER_SIZE ||
        frame_len > XSIAM_WZCP_HEADER_SIZE + body_cap) {
        return -1;
    }

    if (recv_all(sock, hdr, sizeof(hdr)) < 0 ||
        xsiam_wzcp_unpack_header(hdr, h) < 0 ||
        h->body_len != frame_len - XSIAM_WZCP_HEADER_SIZE) {
        return -1;
    }

    if (h->body_len > 0 && recv_all(sock, body, h->body_len) < 0) {
        return -1;
    }

    return (int)h->body_len;
}

static int put_string(unsigned char *out, uint32_t out_cap, uint32_t *off,
                      const char *value)
{
    uint16_t len = value ? (uint16_t)strlen(value) : 0;
    if (*off + 2u + len > out_cap) {
        return -1;
    }
    put_be16(out + *off, len);
    *off += 2;
    if (len > 0) {
        memcpy(out + *off, value, len);
        *off += len;
    }
    return 0;
}

int xsiam_wzcp_build_hello(unsigned char *out, uint32_t out_cap,
                           const char *agent_id, const char *agent_name,
                           const char *agent_version)
{
    uint32_t off = 0;
    if (out_cap < 4) {
        return -1;
    }
    put_be16(out, 1); /* body schema version */
    put_be16(out + 2, 0);
    off = 4;
    if (put_string(out, out_cap, &off, agent_id) < 0 ||
        put_string(out, out_cap, &off, agent_name) < 0 ||
        put_string(out, out_cap, &off, agent_version) < 0) {
        return -1;
    }
    return (int)off;
}

static int put_mac_csv(unsigned char *out, uint32_t out_cap, uint32_t *off,
                       const char *mac_addresses_csv)
{
    char buf[512];
    char *saveptr = NULL;
    char *item;
    uint32_t count_pos;
    uint16_t count = 0;

    if (!mac_addresses_csv || !mac_addresses_csv[0]) {
        if (*off + 2u > out_cap) {
            return -1;
        }
        put_be16(out + *off, 0);
        *off += 2;
        return 0;
    }

    snprintf(buf, sizeof(buf), "%s", mac_addresses_csv);
    if (*off + 2u > out_cap) {
        return -1;
    }
    count_pos = *off;
    *off += 2;

    item = strtok_r(buf, ",", &saveptr);
    while (item && count < 64) {
        while (*item == ' ') {
            item++;
        }
        if (*item && put_string(out, out_cap, off, item) < 0) {
            return -1;
        }
        if (*item) {
            count++;
        }
        item = strtok_r(NULL, ",", &saveptr);
    }

    put_be16(out + count_pos, count);
    return 0;
}

int xsiam_wzcp_build_hello_ex(unsigned char *out, uint32_t out_cap,
                              const char *agent_id, const char *agent_name,
                              const char *agent_version,
                              const char *host_type,
                              const char *mac_addresses_csv)
{
    uint32_t off = 0;
    if (out_cap < 4) {
        return -1;
    }
    put_be16(out, 2); /* body schema version */
    put_be16(out + 2, 0);
    off = 4;
    if (put_string(out, out_cap, &off, agent_id) < 0 ||
        put_string(out, out_cap, &off, agent_name) < 0 ||
        put_string(out, out_cap, &off, agent_version) < 0 ||
        put_string(out, out_cap, &off, host_type) < 0 ||
        put_mac_csv(out, out_cap, &off, mac_addresses_csv) < 0) {
        return -1;
    }
    return (int)off;
}

int xsiam_wzcp_build_event_batch(unsigned char *out, uint32_t out_cap,
                                 uint8_t kind, const char *payload,
                                 size_t payload_len)
{
    uint32_t off = 0;
    if (payload_len > 0xffffu || out_cap < 21u + payload_len) {
        return -1;
    }
    put_be16(out, 1); /* one event */
    out[2] = kind;
    out[3] = 0;
    put_be64(out + 4, xsiam_wzcp_now_ms());
    put_be64(out + 12, xsiam_wzcp_next_seq());
    put_be16(out + 20, (uint16_t)payload_len);
    off = 22;
    if (payload_len > 0) {
        memcpy(out + off, payload, payload_len);
        off += (uint32_t)payload_len;
    }
    return (int)off;
}

int xsiam_wzcp_parse_ack(const unsigned char *body, uint32_t body_len,
                         uint64_t *highest_seq)
{
    if (body_len < 8) {
        return -1;
    }
    *highest_seq = get_be64(body);
    return 0;
}

int xsiam_wzcp_build_ack(unsigned char *out, uint32_t out_cap,
                         uint64_t highest_seq)
{
    if (out_cap < 8) {
        return -1;
    }
    put_be64(out, highest_seq);
    return 8;
}
