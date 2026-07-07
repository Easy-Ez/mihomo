package openvpn

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type memoryPacketIO struct {
	in     <-chan []byte
	out    chan<- []byte
	closed chan struct{}
	once   sync.Once
}

func newMemoryPacketPair() (*memoryPacketIO, *memoryPacketIO) {
	aToB := make(chan []byte, 16)
	bToA := make(chan []byte, 16)
	a := &memoryPacketIO{in: bToA, out: aToB, closed: make(chan struct{})}
	b := &memoryPacketIO{in: aToB, out: bToA, closed: make(chan struct{})}
	return a, b
}

func (m *memoryPacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.closed:
		return nil, net.ErrClosed
	case packet := <-m.in:
		return cloneBytes(packet), nil
	}
}

func (m *memoryPacketIO) WritePacket(ctx context.Context, packet []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.closed:
		return net.ErrClosed
	case m.out <- cloneBytes(packet):
		return nil
	}
}

func (m *memoryPacketIO) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

func (m *memoryPacketIO) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (m *memoryPacketIO) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

func newTestChannels(t *testing.T) (*ControlChannel, *ControlChannel) {
	t.Helper()
	clientIO, serverIO := newMemoryPacketPair()
	clientCrypt, err := NewTLSCrypt(testStaticKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	serverCrypt, err := NewTLSCrypt(testStaticKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))

	client := NewControlChannel(clientIO, clientCrypt, clientID)
	server := NewControlChannel(serverIO, serverCrypt, serverID)
	client.clock = func() time.Time { return time.Unix(1714567890, 0) }
	server.clock = func() time.Time { return time.Unix(1714567891, 0) }
	return client, server
}

func TestControlChannelResetAndAck(t *testing.T) {
	client, server := newTestChannels(t)

	if err := client.SendReset(context.Background()); err != nil {
		t.Fatal(err)
	}
	packet, err := server.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if packet.Opcode != PControlHardResetClientV2 || packet.MessageID != 0 {
		t.Fatalf("unexpected reset packet: %s/%d", packet.Opcode, packet.MessageID)
	}
	if packetID := client.sendPacketID; packetID != 1 {
		t.Fatalf("unexpected first tls-crypt packet id: %d", packetID)
	}
	if server.RemoteSessionID() != client.LocalSessionID() {
		t.Fatalf("server did not learn client session id")
	}

	if err := server.SendAck(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.Read(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline after consuming pure ack, got %v", err)
	}
	if client.PendingMessages() != 0 {
		t.Fatalf("expected client reset to be acked, pending=%d", client.PendingMessages())
	}
}

func TestControlConnCarriesTLSBytes(t *testing.T) {
	client, server := newTestChannels(t)
	client.SetRemoteSessionID(server.LocalSessionID())
	server.SetRemoteSessionID(client.LocalSessionID())

	clientConn := NewControlConn(client)
	serverConn := NewControlConn(server)

	errCh := make(chan error, 1)
	go func() {
		_, err := clientConn.Write([]byte("client tls record"))
		errCh <- err
	}()

	buf := make([]byte, 64)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "client tls record" {
		t.Fatalf("unexpected payload: %q", got)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.Read(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline after consuming pure ack, got %v", err)
	}
	if client.PendingMessages() != 0 {
		t.Fatalf("expected client message to be acked, pending=%d", client.PendingMessages())
	}
}

func TestControlChannelReordersReliableMessages(t *testing.T) {
	packets := make(chan []byte, 4)
	acks := make(chan []byte, 4)
	io := &memoryPacketIO{in: packets, out: acks, closed: make(chan struct{})}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	server := NewControlChannel(io, nil, serverID)

	second, err := (ControlPacket{
		Opcode:       PControlV1,
		LocalSession: clientID,
		MessageID:    1,
		Payload:      []byte("second"),
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	first, err := (ControlPacket{
		Opcode:       PControlV1,
		LocalSession: clientID,
		MessageID:    0,
		Payload:      []byte("first"),
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	packets <- second
	packets <- first

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	packet, err := server.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if packet.MessageID != 0 || string(packet.Payload) != "first" {
		t.Fatalf("unexpected first delivered packet: id=%d payload=%q", packet.MessageID, packet.Payload)
	}
	packet, err = server.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if packet.MessageID != 1 || string(packet.Payload) != "second" {
		t.Fatalf("unexpected second delivered packet: id=%d payload=%q", packet.MessageID, packet.Payload)
	}
}

func TestControlChannelRetransmitsUntilAcked(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))

	control := NewControlChannel(clientIO, nil, clientID)
	now := time.Unix(1714567890, 0)
	control.clock = func() time.Time { return now }

	ctx := context.Background()
	if err := control.SendReset(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packet, _, _, err := DecodeControlPacket(nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Opcode != PControlHardResetClientV2 || packet.MessageID != 0 {
		t.Fatalf("unexpected initial packet: %s/%d", packet.Opcode, packet.MessageID)
	}

	expectNoPacket := func() {
		t.Helper()
		shortCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		if _, err := serverIO.ReadPacket(shortCtx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unexpected retransmission, err=%v", err)
		}
	}

	// 1s after sending: the 2s timer has not expired yet.
	now = now.Add(time.Second)
	wait, err := control.RetransmitDue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if wait != time.Second {
		t.Fatalf("expected 1s until next due, got %s", wait)
	}
	expectNoPacket()

	// 2.5s after sending: due, same message id, backoff doubles to 4s.
	now = now.Add(1500 * time.Millisecond)
	if _, err := control.RetransmitDue(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err = serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packet, _, _, err = DecodeControlPacket(nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Opcode != PControlHardResetClientV2 || packet.MessageID != 0 {
		t.Fatalf("unexpected retransmitted packet: %s/%d", packet.Opcode, packet.MessageID)
	}

	// 3s later: still inside the doubled 4s backoff window.
	now = now.Add(3 * time.Second)
	if _, err := control.RetransmitDue(ctx); err != nil {
		t.Fatal(err)
	}
	expectNoPacket()

	// The peer ACKs message 0: the packet leaves the pending set for good.
	ack, err := (ControlPacket{
		Opcode:           PAckV1,
		LocalSession:     serverID,
		AckIDs:           []uint32{0},
		AckRemoteSession: clientID,
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverIO.WritePacket(ctx, ack); err != nil {
		t.Fatal(err)
	}
	readCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := control.Read(readCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline after consuming pure ack, got %v", err)
	}
	if control.PendingMessages() != 0 {
		t.Fatalf("expected empty pending set, got %d", control.PendingMessages())
	}
	now = now.Add(time.Hour)
	if _, err := control.RetransmitDue(ctx); err != nil {
		t.Fatal(err)
	}
	expectNoPacket()
}

func TestClientWaitServerResetAcksServerReset(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))

	clientControl := NewControlChannel(clientIO, nil, clientID)
	serverControl := NewControlChannel(serverIO, nil, serverID)
	client := &Client{
		config:  &ClientConfig{Proto: ProtoUDP},
		control: clientControl,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := clientControl.SendReset(ctx); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		packet, err := serverControl.Read(ctx)
		if err != nil {
			errCh <- err
			return
		}
		if packet.Opcode != PControlHardResetClientV2 {
			errCh <- errors.New("unexpected reset opcode")
			return
		}
		_, err = serverControl.Send(ctx, PControlHardResetServerV2, nil)
		errCh <- err
	}()

	if err := client.waitServerReset(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if clientControl.PendingMessages() != 0 {
		t.Fatalf("expected client reset to be acked, pending=%d", clientControl.PendingMessages())
	}
	// The client must have ACKed the server reset so the server side is
	// not left retransmitting it.
	readCtx, readCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer readCancel()
	if _, err := serverControl.Read(readCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline after consuming pure ack, got %v", err)
	}
	if serverControl.PendingMessages() != 0 {
		t.Fatalf("expected server reset to be acked, pending=%d", serverControl.PendingMessages())
	}
}

func TestControlConnFragmentsLargeWrites(t *testing.T) {
	client, server := newTestChannels(t)
	client.SetRemoteSessionID(server.LocalSessionID())
	server.SetRemoteSessionID(client.LocalSessionID())
	clientConn := NewControlConn(client)

	payload := bytes.Repeat([]byte{0xAB}, 2*maxControlPayload+123)
	n, err := clientConn.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("short write: %d of %d", n, len(payload))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var got []byte
	packets := 0
	for len(got) < len(payload) {
		packet, err := server.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Opcode != PControlV1 {
			t.Fatalf("unexpected opcode %s", packet.Opcode)
		}
		if len(packet.Payload) > maxControlPayload {
			t.Fatalf("fragment exceeds cap: %d", len(packet.Payload))
		}
		got = append(got, packet.Payload...)
		packets++
	}
	if packets != 3 {
		t.Fatalf("expected 3 fragments, got %d", packets)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("reassembled payload mismatch")
	}
}

func TestSendAckSplitsBacklog(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	control := NewControlChannel(clientIO, nil, clientID)

	control.mu.Lock()
	for i := uint32(0); i < 20; i++ {
		control.ackPending = append(control.ackPending, i)
	}
	control.mu.Unlock()

	ctx := context.Background()
	if err := control.SendAck(ctx); err != nil {
		t.Fatal(err)
	}
	seen := make(map[uint32]bool)
	sizes := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		raw, err := serverIO.ReadPacket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		packet, _, _, err := DecodeControlPacket(nil, raw)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Opcode != PAckV1 {
			t.Fatalf("unexpected opcode %s", packet.Opcode)
		}
		if len(packet.AckIDs) > reliableAckSize {
			t.Fatalf("ack packet exceeds RELIABLE_ACK_SIZE: %d", len(packet.AckIDs))
		}
		sizes = append(sizes, len(packet.AckIDs))
		for _, id := range packet.AckIDs {
			seen[id] = true
		}
	}
	if len(seen) != 20 {
		t.Fatalf("expected 20 distinct acked ids, got %d (sizes %v)", len(seen), sizes)
	}
}

func TestSendCapsPiggybackedAcks(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	control := NewControlChannel(clientIO, nil, clientID)

	control.mu.Lock()
	for i := uint32(0); i < 10; i++ {
		control.ackPending = append(control.ackPending, i)
	}
	control.mu.Unlock()

	ctx := context.Background()
	if _, err := control.Send(ctx, PControlV1, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	raw, err := serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packet, _, _, err := DecodeControlPacket(nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.AckIDs) != controlSendAckMax {
		t.Fatalf("expected %d piggybacked acks, got %d", controlSendAckMax, len(packet.AckIDs))
	}
	control.mu.Lock()
	remaining := len(control.ackPending)
	control.mu.Unlock()
	if remaining != 10-controlSendAckMax {
		t.Fatalf("expected %d acks left in backlog, got %d", 10-controlSendAckMax, remaining)
	}
}

func TestControlChannelSurfacesSoftReset(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	control := NewControlChannel(clientIO, nil, clientID)

	// Simulate a session whose reliable stream has already advanced; the
	// soft reset's message id 0 belongs to a new key session and must not
	// be treated as a stale duplicate of the current stream.
	control.mu.Lock()
	control.recvMessage = 7
	control.mu.Unlock()

	reset, err := (ControlPacket{
		Opcode:       PControlSoftResetV1,
		KeyID:        1,
		LocalSession: serverID,
		MessageID:    0,
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := serverIO.WritePacket(ctx, reset); err != nil {
		t.Fatal(err)
	}
	packet, err := control.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Opcode != PControlSoftResetV1 || packet.KeyID != 1 {
		t.Fatalf("unexpected packet: %s key=%d", packet.Opcode, packet.KeyID)
	}
	control.mu.Lock()
	pendingAcks := len(control.ackPending)
	control.mu.Unlock()
	if pendingAcks != 0 {
		t.Fatalf("soft reset polluted the current ack backlog: %d", pendingAcks)
	}
}

func TestControlConnNotifyAbortsOnSoftReset(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	control := NewControlChannel(clientIO, nil, clientID)
	conn := NewControlConn(control)

	sentinel := errors.New("renegotiation requested")
	conn.SetNotify(func(packet *ControlPacket) error {
		if packet.Opcode == PControlSoftResetV1 {
			return sentinel
		}
		return nil
	})

	reset, err := (ControlPacket{
		Opcode:       PControlSoftResetV1,
		KeyID:        1,
		LocalSession: serverID,
		MessageID:    0,
	}).Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := serverIO.WritePacket(ctx, reset); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); !errors.Is(err, sentinel) {
		t.Fatalf("expected notify error to abort read, got %v", err)
	}
}

func TestTCPPacketIOFraming(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clientIO := NewTCPPacketIO(client)
	serverIO := NewTCPPacketIO(server)
	payload := []byte{1, 2, 3, 4}

	errCh := make(chan error, 1)
	go func() {
		errCh <- clientIO.WritePacket(context.Background(), payload)
	}()

	got, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("unexpected payload: %v", got)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
