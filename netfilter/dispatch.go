package netfilter

import "sync"

var _dispatcher *dispatcher

func init() {
	_dispatcher = &dispatcher{
		queues: make(map[uint16](chan *RawPacket), 1),
	}
}

type dispatcher struct {
	sync.RWMutex
	queues map[uint16]chan *RawPacket
}

func register(qid uint16, c chan *RawPacket) {
	_dispatcher.Lock()
	_dispatcher.queues[qid] = c
	_dispatcher.Unlock()
}

func dispatch(qid uint16, packet *RawPacket) {
	_dispatcher.RLock()
	// TODO: what should happen when this blocks?
	_dispatcher.queues[qid] <- packet
	_dispatcher.RUnlock()
}
