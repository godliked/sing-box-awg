package awg

import "sync"

const packetQueueCapacity = 256

// AWG reads injected packets through its TUN device. The queue owns each
// packet because the caller can recycle its slices as soon as it returns.
type packetQueue struct {
	access  sync.Mutex
	packets chan []byte
	done    chan struct{}
	mtu     int
}

func newPacketQueue(mtu uint32) *packetQueue {
	return &packetQueue{
		packets: make(chan []byte, packetQueueCapacity),
		done:    make(chan struct{}),
		mtu:     int(mtu),
	}
}

func (q *packetQueue) enqueue(slices [][]byte) {
	q.access.Lock()
	defer q.access.Unlock()
	if len(q.packets) == cap(q.packets) {
		return
	}
	select {
	case <-q.done:
		return
	default:
	}
	var size int
	for _, slice := range slices {
		if len(slice) > q.mtu-size {
			return
		}
		size += len(slice)
	}
	if size == 0 {
		return
	}
	packet := make([]byte, 0, size)
	for _, slice := range slices {
		packet = append(packet, slice...)
	}
	q.packets <- packet
}

func (q *packetQueue) close() {
	q.access.Lock()
	defer q.access.Unlock()
	close(q.done)
	for {
		select {
		case <-q.packets:
		default:
			return
		}
	}
}

func copyPacket(buffer []byte, offset int, packet []byte) int {
	if offset > len(buffer) || len(packet) > len(buffer)-offset {
		return 0
	}
	return copy(buffer[offset:], packet)
}
