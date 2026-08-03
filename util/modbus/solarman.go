package modbus

// Solarman (IGEN Tech) data loggers wrap standard Modbus RTU frames in a
// proprietary "V5" envelope on TCP port 8899. The envelope carries the logger's
// serial number, so a plain Modbus client cannot talk to these devices.
//
// This file implements the envelope as a modbus.ClientHandler (Packager,
// Transporter, Connector) plus the meters.Connection wrapper evcc expects, so
// Solarman-attached devices can be used like any other Modbus device.
//
// Frame layout (little endian unless noted):
//
//	A5 | len(2) | control(2) | seq(2) | serial(4) | payload(n) | checksum(1) | 15
//
// Request payload:
//
//	frameType(1) | sensorType(2) | totalTime(4) | powerOnTime(4) | offsetTime(4) | rtuFrame(n)
//
// Response payload carries a 14 byte header followed by the RTU response.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/evcc-io/evcc/util"
	gridx "github.com/grid-x/modbus"
	"github.com/volkszaehler/mbmd/meters"
)

const (
	solarmanPort         = 8899
	solarmanStart        = 0xA5
	solarmanEnd          = 0x15
	solarmanControlCode  = 0x4510 // client request
	solarmanFrameType    = 0x02   // solar inverter
	solarmanReqHeaderLen = 15     // frameType + sensorType + 3 timestamps
	solarmanRespHeader   = 14     // response payload header before the RTU frame
	solarmanEnvelopeLen  = 13     // start + len + control + seq + serial + checksum + end

	rtuMinSize = 4
	rtuMaxSize = 256
)

// solarmanCRC computes the Modbus RTU checksum.
func solarmanCRC(buf []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range buf {
		crc ^= uint16(b)
		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// SolarmanClientHandler implements the Packager, Transporter and Connector
// interfaces for Solarman data loggers.
type SolarmanClientHandler struct {
	Address      string
	Serial       uint32
	Timeout      time.Duration
	ConnectDelay time.Duration
	Logger       gridx.Logger

	mu      sync.Mutex
	slaveID byte
	seq     uint16
	conn    net.Conn
}

// NewSolarmanClientHandler creates a handler for the given logger.
func NewSolarmanClientHandler(address string, serial uint32) *SolarmanClientHandler {
	return &SolarmanClientHandler{
		Address: util.DefaultPort(address, solarmanPort),
		Serial:  serial,
		Timeout: 10 * time.Second,
	}
}

// Clone creates a handler for a different slave sharing the same settings.
func (h *SolarmanClientHandler) Clone() *SolarmanClientHandler {
	return &SolarmanClientHandler{
		Address:      h.Address,
		Serial:       h.Serial,
		Timeout:      h.Timeout,
		ConnectDelay: h.ConnectDelay,
		Logger:       h.Logger,
	}
}

// SetSlave implements the Packager interface.
func (h *SolarmanClientHandler) SetSlave(slaveID byte) {
	h.slaveID = slaveID
}

// Encode implements the Packager interface, producing a plain RTU frame. The
// Solarman envelope is added in Send since it must not be part of the checksum
// the device verifies.
func (h *SolarmanClientHandler) Encode(pdu *gridx.ProtocolDataUnit) ([]byte, error) {
	length := len(pdu.Data) + 4
	if length > rtuMaxSize {
		return nil, fmt.Errorf("modbus: length of data '%v' must not be bigger than '%v'", length, rtuMaxSize)
	}

	adu := make([]byte, length)
	adu[0] = h.slaveID
	adu[1] = pdu.FunctionCode
	copy(adu[2:], pdu.Data)

	checksum := solarmanCRC(adu[:length-2])
	adu[length-2] = byte(checksum)
	adu[length-1] = byte(checksum >> 8)

	return adu, nil
}

// Decode implements the Packager interface.
func (h *SolarmanClientHandler) Decode(adu []byte) (*gridx.ProtocolDataUnit, error) {
	length := len(adu)
	if length < rtuMinSize {
		return nil, fmt.Errorf("modbus: response length '%v' does not meet minimum '%v'", length, rtuMinSize)
	}

	checksum := uint16(adu[length-1])<<8 | uint16(adu[length-2])
	if expect := solarmanCRC(adu[:length-2]); checksum != expect {
		return nil, fmt.Errorf("modbus: response crc '%v' does not match expected '%v'", checksum, expect)
	}

	return &gridx.ProtocolDataUnit{
		FunctionCode: adu[1],
		Data:         adu[2 : length-2],
	}, nil
}

// Verify implements the Packager interface.
//
// Unlike plain RTU the address byte of the response is not compared: Solarman
// loggers substitute it with an unrelated value (a Deye SUN-EVSE11K01 answers
// requests for slave 3 with 0xA2). The checksum verified in Decode covers that
// byte, so frame integrity is still guaranteed, and addressing is handled by
// the logger serial in the envelope rather than by the Modbus address.
func (h *SolarmanClientHandler) Verify(aduRequest, aduResponse []byte) error {
	if length := len(aduResponse); length < rtuMinSize {
		return fmt.Errorf("modbus: response length '%v' does not meet minimum '%v'", length, rtuMinSize)
	}
	if aduResponse[1]&0x7f != aduRequest[1] {
		return fmt.Errorf("modbus: response function code '%v' does not match request '%v'", aduResponse[1]&0x7f, aduRequest[1])
	}
	return nil
}

// wrap embeds an RTU frame in the Solarman envelope.
func (h *SolarmanClientHandler) wrap(rtu []byte) []byte {
	payload := make([]byte, solarmanReqHeaderLen+len(rtu))
	payload[0] = solarmanFrameType
	// sensorType and the three timestamps stay zero for requests
	copy(payload[solarmanReqHeaderLen:], rtu)

	frame := make([]byte, 0, len(payload)+solarmanEnvelopeLen)
	frame = append(frame, solarmanStart)
	frame = binary.LittleEndian.AppendUint16(frame, uint16(len(payload)))
	frame = binary.LittleEndian.AppendUint16(frame, solarmanControlCode)
	frame = binary.LittleEndian.AppendUint16(frame, h.seq)
	frame = binary.LittleEndian.AppendUint32(frame, h.Serial)
	frame = append(frame, payload...)

	var checksum byte
	for _, b := range frame[1:] {
		checksum += b
	}

	return append(frame, checksum, solarmanEnd)
}

// unwrap extracts the RTU frame from a Solarman response.
func (h *SolarmanClientHandler) unwrap(frame []byte) ([]byte, error) {
	if len(frame) < solarmanEnvelopeLen {
		return nil, fmt.Errorf("solarman: response too short: %d bytes", len(frame))
	}
	if frame[0] != solarmanStart || frame[len(frame)-1] != solarmanEnd {
		return nil, errors.New("solarman: invalid frame delimiters")
	}

	payloadLen := int(binary.LittleEndian.Uint16(frame[1:3]))
	if payloadLen < solarmanRespHeader || 11+payloadLen > len(frame)-2 {
		return nil, fmt.Errorf("solarman: invalid payload length %d", payloadLen)
	}

	if serial := binary.LittleEndian.Uint32(frame[7:11]); serial != h.Serial {
		return nil, fmt.Errorf("solarman: response serial %d does not match %d", serial, h.Serial)
	}

	rtu := frame[11+solarmanRespHeader : 11+payloadLen]
	if len(rtu) < rtuMinSize {
		return nil, errors.New("solarman: response contains no modbus frame")
	}

	return rtu, nil
}

// Connect implements the Connector interface.
func (h *SolarmanClientHandler) Connect() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.connect()
}

func (h *SolarmanClientHandler) connect() error {
	if h.conn != nil {
		return nil
	}

	conn, err := net.DialTimeout("tcp", h.Address, h.Timeout)
	if err != nil {
		return err
	}
	h.conn = conn

	if h.ConnectDelay > 0 {
		time.Sleep(h.ConnectDelay)
	}

	return nil
}

// Close implements the Connector interface.
func (h *SolarmanClientHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.close()
}

func (h *SolarmanClientHandler) close() error {
	if h.conn == nil {
		return nil
	}
	err := h.conn.Close()
	h.conn = nil
	return err
}

// Send implements the Transporter interface. It wraps the RTU request, performs
// the exchange and returns the RTU response.
func (h *SolarmanClientHandler) Send(aduRequest []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if err := h.connect(); err != nil {
		return nil, err
	}

	h.seq++
	request := h.wrap(aduRequest)

	if h.Logger != nil {
		h.Logger.Printf("solarman send % x", request)
	}

	response, err := h.exchange(request)
	if err != nil {
		// the logger drops idle connections, so retry once on a fresh socket
		_ = h.close()
		if err := h.connect(); err != nil {
			return nil, err
		}
		if response, err = h.exchange(request); err != nil {
			_ = h.close()
			return nil, err
		}
	}

	if h.Logger != nil {
		h.Logger.Printf("solarman recv % x", response)
	}

	return h.unwrap(response)
}

// exchange writes the request and reads exactly one framed response.
func (h *SolarmanClientHandler) exchange(request []byte) ([]byte, error) {
	if h.Timeout > 0 {
		if err := h.conn.SetDeadline(time.Now().Add(h.Timeout)); err != nil {
			return nil, err
		}
	}

	if _, err := h.conn.Write(request); err != nil {
		return nil, err
	}

	// header carries the payload length, so read it first
	header := make([]byte, 11)
	if _, err := io.ReadFull(h.conn, header); err != nil {
		return nil, err
	}
	if header[0] != solarmanStart {
		return nil, fmt.Errorf("solarman: unexpected start byte 0x%02X", header[0])
	}

	payloadLen := int(binary.LittleEndian.Uint16(header[1:3]))
	if payloadLen < 0 || payloadLen > rtuMaxSize+solarmanRespHeader {
		return nil, fmt.Errorf("solarman: implausible payload length %d", payloadLen)
	}

	rest := make([]byte, payloadLen+2) // payload + checksum + end
	if _, err := io.ReadFull(h.conn, rest); err != nil {
		return nil, err
	}

	return append(header, rest...), nil
}

// SolarmanConnection is a meters.Connection using a Solarman data logger.
type SolarmanConnection struct {
	Client  gridx.Client
	Handler *SolarmanClientHandler
}

var _ meters.Connection = (*SolarmanConnection)(nil)

// NewSolarman creates a Modbus connection through a Solarman data logger.
func NewSolarman(address string, serial uint32) *SolarmanConnection {
	handler := NewSolarmanClientHandler(address, serial)

	return &SolarmanConnection{
		Client:  gridx.NewClient(handler),
		Handler: handler,
	}
}

// String returns the logger address.
func (b *SolarmanConnection) String() string {
	return b.Handler.Address
}

// ModbusClient returns the Modbus client.
func (b *SolarmanConnection) ModbusClient() gridx.Client {
	return b.Client
}

// Logger sets a logging instance for physical bus operations.
func (b *SolarmanConnection) Logger(l meters.Logger) {
	b.Handler.Logger = l
}

// Slave sets the Modbus device id for the following operations.
func (b *SolarmanConnection) Slave(deviceID uint8) {
	b.Handler.SetSlave(deviceID)
}

// Timeout sets the Modbus timeout.
func (b *SolarmanConnection) Timeout(timeout time.Duration) time.Duration {
	t := b.Handler.Timeout
	b.Handler.Timeout = timeout
	return t
}

// ConnectDelay sets the initial delay after connecting before starting communication.
func (b *SolarmanConnection) ConnectDelay(delay time.Duration) {
	b.Handler.ConnectDelay = delay
}

// Close closes the Modbus connection.
func (b *SolarmanConnection) Close() {
	_ = b.Handler.Close()
}

// Clone clones the Modbus connection.
func (b *SolarmanConnection) Clone(deviceID byte) meters.Connection {
	handler := b.Handler.Clone()
	handler.SetSlave(deviceID)

	return &SolarmanConnection{
		Client:  gridx.NewClient(handler),
		Handler: handler,
	}
}
