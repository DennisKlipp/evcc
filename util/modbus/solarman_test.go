package modbus

import (
	"encoding/hex"
	"testing"

	gridx "github.com/grid-x/modbus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reference frames captured from a Deye SUN-EVSE11K01 attached to a Solarman
// logger (serial 3493601102, slave 3), reading holding register 57
const (
	refSerial = 3493601102
	refSlave  = 3
	refRTU    = "03030039000155e5"
	refFrame  = "a51700104501004e1f3cd002000000000000000000000000000003030039000155e56215"
)

func refHandler(t *testing.T) *SolarmanClientHandler {
	t.Helper()
	h := NewSolarmanClientHandler("192.0.2.1", refSerial)
	h.SetSlave(refSlave)
	return h
}

func TestSolarmanEncode(t *testing.T) {
	h := refHandler(t)

	// read holding registers 57, count 1
	adu, err := h.Encode(&gridx.ProtocolDataUnit{
		FunctionCode: gridx.FuncCodeReadHoldingRegisters,
		Data:         []byte{0x00, 0x39, 0x00, 0x01},
	})
	require.NoError(t, err)
	assert.Equal(t, refRTU, hex.EncodeToString(adu))
}

func TestSolarmanWrap(t *testing.T) {
	h := refHandler(t)
	h.seq = 1

	rtu, err := hex.DecodeString(refRTU)
	require.NoError(t, err)

	assert.Equal(t, refFrame, hex.EncodeToString(h.wrap(rtu)))
}

func TestSolarmanUnwrap(t *testing.T) {
	h := refHandler(t)

	// response as returned by the device: envelope with a 14 byte payload header
	// followed by the RTU response (slave, fn, bytecount, 0x01A0 = 416, crc)
	rtuResp := []byte{0x03, 0x03, 0x02, 0x01, 0xA0}
	rtuResp = append(rtuResp, byte(solarmanCRC(rtuResp)), byte(solarmanCRC(rtuResp)>>8))

	payload := make([]byte, solarmanRespHeader)
	payload = append(payload, rtuResp...)

	frame := []byte{solarmanStart}
	frame = append(frame, byte(len(payload)), byte(len(payload)>>8))
	frame = append(frame, 0x11, 0x15) // response control code
	frame = append(frame, 0x01, 0x00) // sequence
	frame = append(frame, 0x4e, 0x1f, 0x3c, 0xd0)
	frame = append(frame, payload...)
	frame = append(frame, 0x00, solarmanEnd)

	got, err := h.unwrap(frame)
	require.NoError(t, err)
	assert.Equal(t, rtuResp, got)

	// and the RTU layer must decode it back to the register value
	pdu, err := h.Decode(got)
	require.NoError(t, err)
	assert.Equal(t, uint16(416), uint16(pdu.Data[1])<<8|uint16(pdu.Data[2]))
}

func TestSolarmanUnwrapRejects(t *testing.T) {
	h := refHandler(t)

	valid, err := hex.DecodeString(refFrame)
	require.NoError(t, err)

	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"zu kurz", valid[:5]},
		{"falsches Startbyte", append([]byte{0x00}, valid[1:]...)},
		{"falsche Seriennummer", func() []byte {
			f := append([]byte(nil), valid...)
			f[7] ^= 0xFF
			return f
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.unwrap(tc.frame)
			assert.Error(t, err)
		})
	}
}

func TestSolarmanDecodeRejectsBadCRC(t *testing.T) {
	h := refHandler(t)

	adu := []byte{0x03, 0x03, 0x02, 0x01, 0xA0, 0x00, 0x00}
	_, err := h.Decode(adu)
	assert.Error(t, err)
}

func TestSolarmanVerify(t *testing.T) {
	h := refHandler(t)

	req := []byte{0x03, 0x03, 0x00, 0x39}

	assert.NoError(t, h.Verify(req, []byte{0x03, 0x03, 0x02, 0x01, 0xA0, 0x00, 0x00}))

	// the device answers requests for slave 3 with address 0xA2, which must be
	// tolerated - captured from a Deye SUN-EVSE11K01
	assert.NoError(t, h.Verify(req, []byte{0xA2, 0x03, 0x02, 0x01, 0xA0, 0x00, 0x00}),
		"solarman substitutes the address byte")

	assert.Error(t, h.Verify(req, []byte{0x03, 0x04, 0x02, 0x01, 0xA0, 0x00, 0x00}), "function code mismatch")
	assert.Error(t, h.Verify(req, []byte{0x03}), "too short")
}

// TestSolarmanRealResponse decodes a response captured from a Deye
// SUN-EVSE11K01 (register 57, no vehicle connected)
func TestSolarmanRealResponse(t *testing.T) {
	h := refHandler(t)

	frame, err := hex.DecodeString("a51500101501674e1f3cd002011c9a0e30850c0000bf5b623aa203020181bdadec15")
	require.NoError(t, err)

	rtu, err := h.unwrap(frame)
	require.NoError(t, err)
	assert.Equal(t, "a203020181bdad", hex.EncodeToString(rtu))

	require.NoError(t, h.Verify([]byte{0x03, 0x03, 0x00, 0x39}, rtu))

	pdu, err := h.Decode(rtu)
	require.NoError(t, err)
	assert.Equal(t, uint16(385), uint16(pdu.Data[1])<<8|uint16(pdu.Data[2]), "status word = idle")
}
