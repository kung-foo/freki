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

/*
Package netfilter contains Go bindings for libnetfilter_queue

This library provides access to packets in the IPTables netfilter queue (NFQUEUE).
The libnetfilter_queue library is part of the http://netfilter.org/projects/libnetfilter_queue/ project.
*/
package netfilter

/*
#cgo pkg-config: libnetfilter_queue
#cgo CFLAGS: -Wall -Werror -I/usr/include
#cgo LDFLAGS: -L/usr/lib64/

#include "netfilter.h"
*/
import "C"

import (
	"unsafe"

	"github.com/pkg/errors"
)

// Queue is an interface to packets that have been queued by the kernel packet
// filter.
type Queue struct {
	// ID is the queue-num from iptables
	ID      uint16
	h       *C.struct_nfq_handle
	qh      *C.struct_nfq_q_handle
	fd      C.int
	packets chan *RawPacket
}

// RawPacket is struct that holds the packet data and the id of the queue it
// came from.
type RawPacket struct {
	// ID is the queue-num from iptables
	ID uint32

	// Data is raw packet _not_ including the physical header.
	Data []byte
}

// Verdict is a type alias of u_int32_t
type Verdict C.uint

// NF_* verdicts
const (
	NF_DROP   Verdict = 0
	NF_ACCEPT Verdict = 1
	NF_STOLEN Verdict = 2
	NF_QUEUE  Verdict = 3
	NF_REPEAT Verdict = 4
	NF_STOP   Verdict = 5
)

const (
	AF_INET                       = 2
	NF_DEFAULT_PACKET_SIZE uint32 = 0xffff
)

// New creates a new Queue with the given queue id.
func New(queueID uint16, maxPacketsInQueue uint32, packetSize uint32) (nfq *Queue, err error) {
	nfq = &Queue{
		ID: queueID,
		// TODO: what should the chan size be?
		packets: make(chan *RawPacket, 1024),
	}
	var ret C.int

	defer func() {
		if err != nil && nfq != nil {
			if nfq.qh != nil {
				C.nfq_destroy_queue(nfq.qh)
			}

			if nfq.h != nil {
				C.nfq_close(nfq.h)
			}
		}
	}()

	if nfq.h, err = C.nfq_open(); err != nil {
		err = errors.Wrap(err, "netfilter: unable to open nfq queue handle.")
		return
	}

	if ret, err = C.nfq_unbind_pf(nfq.h, AF_INET); err != nil || ret < 0 {
		err = errors.Wrap(err, "netfilter: unable to unbind existing nfq handler.")
		return
	}

	if ret, err = C.nfq_bind_pf(nfq.h, AF_INET); err != nil || ret < 0 {
		err = errors.Wrap(err, "netfilter: unable to bind to AF_INET protocol family.")
		return
	}

	if nfq.qh, err = C.CreateQueue(nfq.h, C.u_int16_t(queueID)); err != nil || nfq.qh == nil {
		err = errors.Wrap(err, "netfilter: unable to create nfq queue.")
		return
	}

	if ret, err = C.nfq_set_queue_maxlen(nfq.qh, C.u_int32_t(maxPacketsInQueue)); err != nil || ret < 0 {
		err = errors.Wrap(err, "netfilter: unable to set nfq max queue length.")
		return
	}

	if C.nfq_set_mode(nfq.qh, C.u_int8_t(2), C.uint(packetSize)) < 0 {
		err = errors.Wrap(err, "netfilter: unable to set packet copy mode.")
		return
	}

	if nfq.fd, err = C.nfq_fd(nfq.h); err != nil {
		err = errors.Wrap(err, "netfilter: unable to get nfq queue file-descriptor.")
		return

	}

	// TODO: error handling
	// me: https://i.imgur.com/Lmy5P.gif
	C.nfnl_rcvbufsiz(C.nfq_nfnlh(nfq.h), 1024*16384)

	// register this queue object with the global dispatcher
	register(queueID, nfq.packets)

	return
}

// Close unbinds the nfq queue
func (nfq *Queue) Close() {
	// TODO: why does this hang sometimes?
	// log.Print("nfq_destroy_queue")
	// C.nfq_destroy_queue(nfq.qh)

	C.nfq_close(nfq.h)
}

// Packets returns a channel of RawPackets
func (nfq *Queue) Packets() <-chan *RawPacket {
	return nfq.packets
}

// SetVerdict tells nfq how to handle the packet.
func (nfq *Queue) SetVerdict(packet *RawPacket, verdict Verdict) (err error) {
	// TODO: make functions explicit. for example: SetVerdictAccept, SetVerdictDrop
	// TODO: get error
	C.nfq_set_verdict(
		nfq.qh,
		C.u_int32_t(packet.ID),
		C.u_int32_t(verdict),
		0,
		nil,
	)
	return
}

// SetVerdictModifed tells nfq that the packet should be replaced with what is
// in buffer.
func (nfq *Queue) SetVerdictModifed(packet *RawPacket, buffer []byte, verdict Verdict) (err error) {
	C.nfq_set_verdict(
		nfq.qh,
		C.u_int32_t(packet.ID),
		C.u_int32_t(verdict),
		C.u_int32_t(len(buffer)),
		(*C.uchar)(unsafe.Pointer(&buffer[0])),
	)
	return
}

// Run starts reading packets and dispatching them to the designated handlers.
// This is a blocking call and should be run from its own go routine.
func (nfq *Queue) Run() {
	C.Run(nfq.h, nfq.fd)
}

//export go_callback
func go_callback(id C.int, data *C.uchar, len C.int, queue_id C.int) {
	// TODO: check cast of id
	payload := &RawPacket{
		ID:   uint32(id),
		Data: C.GoBytes(unsafe.Pointer(data), len),
	}

	dispatch(uint16(queue_id), payload)
}
