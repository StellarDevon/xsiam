#ifndef XSIAM_WZCP_H
#define XSIAM_WZCP_H

#include <stdint.h>
#include <stddef.h>

#define XSIAM_WZCP_MAGIC 0x575A4350u /* WZCP */
#define XSIAM_WZCP_VERSION 1
#define XSIAM_WZCP_HEADER_SIZE 32
#define XSIAM_WZCP_MAX_FRAME (1024u * 1024u)

enum xsiam_wzcp_msg_type {
    XSIAM_WZCP_MSG_HELLO = 1,
    XSIAM_WZCP_MSG_EVENT_BATCH = 2,
    XSIAM_WZCP_MSG_ACK = 3,
    XSIAM_WZCP_MSG_HEARTBEAT = 4,
    XSIAM_WZCP_MSG_CONTROL = 5,
    XSIAM_WZCP_MSG_ERROR = 6
};

enum xsiam_wzcp_event_kind {
    XSIAM_WZCP_EVENT_LOG = 1,
    XSIAM_WZCP_EVENT_CONTROL = 2
};

struct xsiam_wzcp_header {
    uint32_t magic;
    uint8_t version;
    uint8_t header_len;
    uint8_t flags;
    uint8_t msg_type;
    uint32_t agent_id;
    uint64_t seq;
    uint64_t timestamp_ms;
    uint32_t body_len;
};

int xsiam_wzcp_enabled(void);
const char *xsiam_wzcp_agent_uuid(void);
const char *xsiam_wzcp_host_type(void);
int xsiam_wzcp_collect_mac_addresses(char *out, size_t out_size);
uint64_t xsiam_wzcp_now_ms(void);
uint64_t xsiam_wzcp_next_seq(void);
void xsiam_wzcp_pack_header(unsigned char *out, const struct xsiam_wzcp_header *h);
int xsiam_wzcp_unpack_header(const unsigned char *in, struct xsiam_wzcp_header *h);
int xsiam_wzcp_send_frame(int sock, uint8_t msg_type, uint32_t agent_id,
                          uint64_t seq, const void *body, uint32_t body_len);
int xsiam_wzcp_recv_frame(int sock, struct xsiam_wzcp_header *h,
                          unsigned char *body, uint32_t body_cap);
int xsiam_wzcp_build_hello(unsigned char *out, uint32_t out_cap,
                           const char *agent_id, const char *agent_name,
                           const char *agent_version);
int xsiam_wzcp_build_hello_ex(unsigned char *out, uint32_t out_cap,
                              const char *agent_id, const char *agent_name,
                              const char *agent_version,
                              const char *host_type,
                              const char *mac_addresses_csv);
int xsiam_wzcp_build_event_batch(unsigned char *out, uint32_t out_cap,
                                 uint8_t kind, const char *payload,
                                 size_t payload_len);
int xsiam_wzcp_parse_ack(const unsigned char *body, uint32_t body_len,
                         uint64_t *highest_seq);
int xsiam_wzcp_build_ack(unsigned char *out, uint32_t out_cap,
                         uint64_t highest_seq);

#endif
