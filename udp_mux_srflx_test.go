//go:build !js
// +build !js

package ice

//nolint:gosec
import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun"
	"github.com/pion/transport/test"
	"github.com/stretchr/testify/require"
)

func TestUDPMuxSrflx(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	conn, err := net.ListenUDP(udp, &net.UDPAddr{})
	require.NoError(t, err)

	udpMux := NewUDPMuxSrflxDefault(UDPMuxSrflxParams{
		Logger:  nil,
		UDPConn: conn,
	})

	defer func() {
		_ = udpMux.Close()
		_ = conn.Close()
	}()

	require.NotNil(t, udpMux.LocalAddr(), "tcpMux.LocalAddr() is nil")

	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		testMuxSrflxConnection(t, udpMux, "ufrag4", udp)
	}()

	wg.Wait()

	require.NoError(t, udpMux.Close())

	// can't create more connections
	_, err = udpMux.GetConn("failufrag")
	require.Error(t, err)
}

func testMuxSrflxConnection(t *testing.T, udpMux *UDPMuxSrflxDefault, ufrag string, network string) {
	pktConn, err := udpMux.GetConn(ufrag)
	require.NoError(t, err, "error retrieving muxed connection for ufrag")
	defer func() {
		_ = pktConn.Close()
	}()

	remoteConn, err := net.DialUDP(network, nil, &net.UDPAddr{
		Port: udpMux.LocalAddr().(*net.UDPAddr).Port,
	})
	require.NoError(t, err, "error dialing test udp connection")
	defer func() {
		_ = remoteConn.Close()
	}()

	// use small value for TTL to check expiration of the address
	udpMux.params.XORMappedAddrCacheTTL = time.Millisecond * 20
	testXORIP := net.ParseIP("213.141.156.236")
	testXORPort := 21254

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		address, err := udpMux.GetXORMappedAddr(remoteConn.LocalAddr(), time.Second)
		require.NoError(t, err)
		require.NotNil(t, address)
		require.True(t, address.IP.Equal(testXORIP))
		require.Equal(t, address.Port, testXORPort)
	}()

	// wait until GetXORMappedAddr calls sendStun method
	time.Sleep(time.Millisecond)

	// check that mapped address filled correctly after sent stun
	udpMux.mu.Lock()
	mappedAddr, ok := udpMux.xorMappedAddr[remoteConn.LocalAddr().String()]
	require.True(t, ok)
	require.NotNil(t, mappedAddr)
	require.True(t, mappedAddr.pending())
	require.False(t, mappedAddr.expired())
	udpMux.mu.Unlock()

	// clean receiver read buffer
	buf := make([]byte, receiveMTU)
	_, err = remoteConn.Read(buf)
	require.NoError(t, err)

	// write back to udpMux XOR message with address
	msg := stun.New()
	msg.Type = stun.MessageType{Method: stun.MethodBinding, Class: stun.ClassRequest}
	msg.Add(stun.AttrUsername, []byte(ufrag+":otherufrag"))
	addr := &stun.XORMappedAddress{
		IP:   testXORIP,
		Port: testXORPort,
	}
	err = addr.AddTo(msg)
	require.NoError(t, err)

	msg.Encode()
	_, err = remoteConn.Write(msg.Raw)
	require.NoError(t, err)

	// wait for the packet to be consumed and parsed by udpMux
	wg.Wait()

	// we should get address immediately from the cached map
	address, err := udpMux.GetXORMappedAddr(remoteConn.LocalAddr(), time.Second)
	require.NoError(t, err)
	require.NotNil(t, address)

	udpMux.mu.Lock()
	// check mappedAddr is not pending, we didn't send stun twice
	require.False(t, mappedAddr.pending())

	// check expiration by TTL
	time.Sleep(time.Millisecond * 21)
	require.True(t, mappedAddr.expired())
	udpMux.mu.Unlock()

	// after expire, we send stun request again
	// but we not receive response in 5 milliseconds and should get error here
	address, err = udpMux.GetXORMappedAddr(remoteConn.LocalAddr(), time.Millisecond*5)
	require.NotNil(t, err)
	require.Nil(t, address)
}
