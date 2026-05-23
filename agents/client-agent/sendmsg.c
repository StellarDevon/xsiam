/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "os_net/os_net.h"
#include "xsiam_wzcp.h"

static pthread_mutex_t send_mutex;

/* Initialize sender structure */
void sender_init() {
    w_mutex_init(&send_mutex, NULL);
}

/* Send a message to the server */
int send_msg(const char *msg, ssize_t msg_length)
{
    ssize_t msg_size;
    char crypt_msg[OS_MAXSTR + 1];
    unsigned char wzcp_body[OS_MAXSTR + 128];
    int retval;
    int error;

    if (xsiam_wzcp_enabled()) {
        size_t plain_len = msg_length < 0 ? strlen(msg) : (size_t) msg_length;
        int body_len = xsiam_wzcp_build_event_batch(wzcp_body, sizeof(wzcp_body),
                                                    XSIAM_WZCP_EVENT_LOG,
                                                    msg, plain_len);
        if (body_len < 0) {
            merror("Unable to build WZCP event batch.");
            return -1;
        }

        retval = xsiam_wzcp_send_frame(agt->sock, XSIAM_WZCP_MSG_EVENT_BATCH,
                                       (uint32_t) atoi(keys.keyentries[0]->id),
                                       xsiam_wzcp_next_seq(),
                                       wzcp_body, (uint32_t) body_len);
        if (retval == 0) {
            w_agentd_state_update(INCREMENT_MSG_SEND, NULL);
        }
        else {
            mwarn(SEND_ERROR, "gateway", "WZCP send failed");
            sleep(1);
        }
        return retval;
    }

    msg_size = CreateSecMSG(&keys, msg, msg_length < 0 ? strlen(msg) : (size_t)msg_length, crypt_msg, 0);
    if (msg_size <= 0) {
        merror(SEC_ERROR);
        return (-1);
    }

    /* Send msg_size of crypt_msg */
    if (agt->server[agt->rip_id].protocol == IPPROTO_UDP) {
        retval = OS_SendUDPbySize(agt->sock, msg_size, crypt_msg);
#ifndef WIN32
        error = errno;
#endif
    } else {
        w_mutex_lock(&send_mutex);
        retval = OS_SendSecureTCP(agt->sock, msg_size, crypt_msg);
#ifndef WIN32
        error = errno;
#endif
        w_mutex_unlock(&send_mutex);
    }

    if (!retval) {
        w_agentd_state_update(INCREMENT_MSG_SEND, NULL);
    } else {
#ifdef WIN32
        error = WSAGetLastError();
        mwarn(SEND_ERROR, "server", win_strerror(error));
#else
        switch (error) {
        case EPIPE:
            mdebug2(TCP_EPIPE);
            break;
        case ECONNREFUSED:
            mdebug2(CONN_REF);
            break;
        default:
            mwarn(SEND_ERROR, "server", strerror(error));
            break;
        }

#endif
        sleep(1);
    }

    return retval;
}
