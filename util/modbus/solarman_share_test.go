package modbus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// clones must share the transport: the logger accepts only one connection
func TestSolarmanCloneSharesTransport(t *testing.T) {
	h := NewSolarmanClientHandler("192.0.2.1", 123456)
	h.SetSlave(3)

	c := h.Clone()
	c.SetSlave(5)

	assert.Same(t, h.solarmanTransport, c.solarmanTransport, "transport must be shared")
	assert.Equal(t, byte(3), h.slaveID, "original slave unchanged")
	assert.Equal(t, byte(5), c.slaveID, "clone has its own slave")
}

// the meters.Connection clone must share it too
func TestSolarmanConnectionCloneSharesTransport(t *testing.T) {
	conn := NewSolarman("192.0.2.1", 123456)
	clone := conn.Clone(5).(*SolarmanConnection)

	assert.Same(t, conn.Handler.solarmanTransport, clone.Handler.solarmanTransport)
}
