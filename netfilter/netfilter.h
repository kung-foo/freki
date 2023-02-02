/*
   Copyright 2014 Krishna Raman <kraman@gmail.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef _NETFILTER_H
#define _NETFILTER_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define PASSTHROUGH 0

extern void go_callback(int id, unsigned char* data, int len, int queue_id);

static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *cb_data){
    uint32_t id = -1;
    struct nfqnl_msg_packet_hdr *ph = NULL;
    unsigned char *buffer = NULL;
    int ret = 0;

    // nfq_get_packet_hw
    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);

    if (PASSTHROUGH) {
        if (nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL) == -1) {
            perror("nfq_set_verdict");
        }
    } else {
        ret = nfq_get_payload(nfa, &buffer);
        go_callback(id, buffer, ret, (intptr_t)cb_data);
    }

    return ret;
}

static inline struct nfq_q_handle* CreateQueue(struct nfq_handle *h, uint16_t queue)
{
    return nfq_create_queue(h, queue, &nf_callback, (void *)(intptr_t)queue);
}

static inline void Run(struct nfq_handle *h, int fd)
{
    char buf[70000] __attribute__ ((aligned));
    int sz, rv;

    //int opt = 1;
    //setsockopt(fd, SOL_NETLINK, NETLINK_BROADCAST_SEND_ERROR, &opt, sizeof(int));
    //setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));

    // MSG_DONTWAIT?

    while ((sz = recv(fd, buf, sizeof(buf), 0)) && sz >= 0) {
        if (sz == sizeof(buf)) {
            // TODO: something
        }
        if ((rv = nfq_handle_packet(h, buf, sz)) && rv != 0) {
            // perror("nfq_handle_packet");
        }
    }
}

#endif
