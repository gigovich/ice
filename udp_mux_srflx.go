package ice

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/logging"
	"github.com/pion/stun"
)

// UDPMuxSrflx allows multiple connections to go over a single UDP port for
// server reflexive candidates.
type UDPMuxSrflx interface {
	UDPMux
	GetXORMappedAddr(serverAddr net.Addr, deadline time.Duration) (*stun.XORMappedAddress, error)
}

type UDPMuxSrflxDefault struct {
	*UDPMuxDefault
	params UDPMuxSrflxParams

	// since we have a shared socket, for srflx candidates it makes sense to have a shared mapped address across all the agents
	// stun.XORMappedAddress indexed by the STUN server addr
	xorMappedAddr map[string]*xorAddrMap
}

// UDPMuxSrflxParams are parameters for UDPMux server reflexive.
type UDPMuxSrflxParams struct {
	Logger                logging.LeveledLogger
	UDPConn               net.PacketConn
	XORMappedAddrCacheTTL time.Duration
}

// NewUDPMuxDefault creates an implementation of UDPMux
func NewUDPMuxSrflxDefault(params UDPMuxSrflxParams) *UDPMuxSrflxDefault {
	if params.Logger == nil {
		params.Logger = logging.NewDefaultLoggerFactory().NewLogger("ice")
	}
	if params.XORMappedAddrCacheTTL == 0 {
		params.XORMappedAddrCacheTTL = time.Second * 25
	}

	m := &UDPMuxSrflxDefault{
		params:        params,
		xorMappedAddr: make(map[string]*xorAddrMap),
	}

	// wrap UDP connection, process server reflexieve messages
	// before they passed to UDPMux connection handler
	m.params.UDPConn = &srflxConn{
		PacketConn: params.UDPConn,
		mux:        m,
		logger:     params.Logger,
	}

	// embed UDPMux
	udpMuxParams := UDPMuxParams{
		Logger:  params.Logger,
		UDPConn: m.params.UDPConn,
	}
	m.UDPMuxDefault = NewUDPMuxDefault(udpMuxParams)

	return m
}

func (m *UDPMuxSrflxDefault) handleXORMappedResponse(stunAddr *net.UDPAddr, msg *stun.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mappedAddr, ok := m.xorMappedAddr[stunAddr.String()]
	if !ok {
		return fmt.Errorf("no address map for %v", stunAddr)
	}

	var addr stun.XORMappedAddress
	if err := addr.GetFrom(msg); err != nil {
		return err
	}

	m.xorMappedAddr[stunAddr.String()] = mappedAddr
	mappedAddr.SetAddr(&addr)

	return nil
}

// isXORMappedResponse indicates whether the message is a XORMappedAddress response from the STUN server
func isXORMappedResponse(msg *stun.Message) bool {
	_, err := msg.Get(stun.AttrXORMappedAddress)
	return err == nil
}

// GetXORMappedAddr returns *stun.XORMappedAddress if already present for a given STUN server.
//
// Makes a STUN binding request to discover mapped address otherwise.
// Blocks until the response is received. The response will be handled by UDPMuxDefault.connWorker
// Method is safe for concurrent use.
func (m *UDPMuxSrflxDefault) GetXORMappedAddr(serverAddr net.Addr, deadline time.Duration) (*stun.XORMappedAddress, error) {
	m.mu.Lock()
	mappedAddr, ok := m.xorMappedAddr[serverAddr.String()]
	// if we already have a mapping for this STUN server (address already received)
	// and if it is not too old we return it without making a new request to STUN server
	if ok {
		if mappedAddr.expired() {
			mappedAddr.closeWaiters()
			delete(m.xorMappedAddr, serverAddr.String())
			ok = false
		} else if mappedAddr.pending() {
			ok = false
		}
	}
	m.mu.Unlock()
	if ok {
		return mappedAddr.addr, nil
	}

	// otherwise, make a STUN request to discover the address
	// or wait for already sent request to complete
	waitAddrReceived, err := m.sendStun(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("could not send STUN request: %v", err)
	}

	// block until response was handled by the connWorker routine and XORMappedAddress was updated
	select {
	case <-waitAddrReceived:
		// when channel closed, addr was obtained
		m.mu.Lock()
		mappedAddr := *m.xorMappedAddr[serverAddr.String()]
		m.mu.Unlock()
		if mappedAddr.addr == nil {
			return nil, fmt.Errorf("no XORMappedAddress for %s", serverAddr.String())
		}
		return mappedAddr.addr, nil
	case <-time.After(deadline):
		return nil, fmt.Errorf("timeout while waiting for XORMappedAddr")
	}
}

// sendStun sends a STUN request via UDP conn.
//
// The returned channel is closed when the STUN response has been received.
// Method is safe for concurrent use.
func (m *UDPMuxSrflxDefault) sendStun(serverAddr net.Addr) (chan struct{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// if record present in the map, we already sent a STUN request,
	// just wait when waitAddrRecieved will be closed
	addrMap, ok := m.xorMappedAddr[serverAddr.String()]
	if !ok {
		addrMap = &xorAddrMap{
			expiresAt:        time.Now().Add(m.params.XORMappedAddrCacheTTL),
			waitAddrReceived: make(chan struct{}),
		}
		m.xorMappedAddr[serverAddr.String()] = addrMap
	}

	req, err := stun.Build(stun.BindingRequest, stun.TransactionID)
	if err != nil {
		return nil, err
	}

	if _, err = m.params.UDPConn.WriteTo(req.Raw, serverAddr); err != nil {
		return nil, err
	}

	return addrMap.waitAddrReceived, nil
}

type srflxConn struct {
	net.PacketConn
	mux    *UDPMuxSrflxDefault
	logger logging.LeveledLogger
}

func (c *srflxConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		// message about this err will be logged in the UDPMux
		return
	}

	if stun.IsMessage(p[:n]) {
		msg := &stun.Message{
			Raw: append([]byte{}, p[:n]...),
		}

		if err = msg.Decode(); err != nil {
			c.logger.Warnf("Failed to handle decode ICE from %s: %v\n", addr.String(), err)
			return n, addr, nil
		}

		if isXORMappedResponse(msg) {
			err = c.mux.handleXORMappedResponse(udpAddr, msg)
			if err != nil {
				c.logger.Errorf("%w: %v", errGetXorMappedAddrResponse, err)
			}
			return c.PacketConn.ReadFrom(p)
		}
	}
	return
}

type xorAddrMap struct {
	addr             *stun.XORMappedAddress
	waitAddrReceived chan struct{}
	expiresAt        time.Time
}

func (a *xorAddrMap) closeWaiters() {
	select {
	case <-a.waitAddrReceived:
		// notify was close, ok, that means we received duplicate response
		// just exit
		break
	default:
		// notify tha twe have a new addr
		close(a.waitAddrReceived)
	}
}

func (a *xorAddrMap) pending() bool {
	return a.addr == nil
}

func (a *xorAddrMap) expired() bool {
	return a.expiresAt.Before(time.Now())
}

func (a *xorAddrMap) SetAddr(addr *stun.XORMappedAddress) {
	a.addr = addr
	a.closeWaiters()
}
