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
Go bindings for libnetfilter_queue

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
	"fmt"
	"unsafe"
)

type Queue struct {
	h       *C.struct_nfq_handle
	qh      *C.struct_nfq_q_handle
	fd      C.int
	packets chan *RawPacket
}

type RawPacket struct {
	ID   uint32
	Data []byte
}

//Verdict for a packet
type Verdict C.uint

const (
	AF_INET = 2

	NF_DROP   Verdict = 0
	NF_ACCEPT Verdict = 1
	NF_STOLEN Verdict = 2
	NF_QUEUE  Verdict = 3
	NF_REPEAT Verdict = 4
	NF_STOP   Verdict = 5

	NF_DEFAULT_PACKET_SIZE uint32 = 0xffff
)

//Create and bind to queue specified by queueId
func New(queueID uint16, maxPacketsInQueue uint32, packetSize uint32) (*Queue, error) {
	var nfq = Queue{
		// TODO: what should the chan size be?
		packets: make(chan *RawPacket, 1024),
	}
	var err error
	var ret C.int

	if nfq.h, err = C.nfq_open(); err != nil {
		return nil, fmt.Errorf("Error opening Queue handle: %v\n", err)
	}

	if ret, err = C.nfq_unbind_pf(nfq.h, AF_INET); err != nil || ret < 0 {
		return nil, fmt.Errorf("Error unbinding existing NFQ handler from AF_INET protocol family: %v\n", err)
	}

	if ret, err := C.nfq_bind_pf(nfq.h, AF_INET); err != nil || ret < 0 {
		return nil, fmt.Errorf("Error binding to AF_INET protocol family: %v\n", err)
	}

	if nfq.qh, err = C.CreateQueue(nfq.h, C.u_int16_t(queueID)); err != nil || nfq.qh == nil {
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Error binding to queue: %v\n", err)
	}

	if ret, err = C.nfq_set_queue_maxlen(nfq.qh, C.u_int32_t(maxPacketsInQueue)); err != nil || ret < 0 {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Unable to set max packets in queue: %v\n", err)
	}

	if C.nfq_set_mode(nfq.qh, C.u_int8_t(2), C.uint(packetSize)) < 0 {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Unable to set packets copy mode: %v\n", err)
	}

	if nfq.fd, err = C.nfq_fd(nfq.h); err != nil {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Unable to get queue file-descriptor. %v", err)
	}

	register(queueID, nfq.packets)

	// go nfq.run()

	return &nfq, nil
}

//Unbind and close the queue
func (nfq *Queue) Close() {
	//log.Print("nfq_destroy_queue")
	//C.nfq_destroy_queue(nfq.qh)

	C.nfq_close(nfq.h)
}

func (nfq *Queue) Packets() <-chan *RawPacket {
	return nfq.packets
}

// TODO: make functions explicit. for example: SetVerdictAccept, SetVerdictDrop
func (nfq *Queue) SetVerdict(packet *RawPacket, verdict Verdict) (err error) {
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

func (nfq *Queue) SetVerdictModifed(packet *RawPacket, verdict Verdict) (err error) {
	C.nfq_set_verdict(
		nfq.qh,
		C.u_int32_t(packet.ID),
		C.u_int32_t(verdict),
		C.u_int32_t(len(packet.Data)),
		(*C.uchar)(unsafe.Pointer(&packet.Data[0])),
	)
	return
}

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
