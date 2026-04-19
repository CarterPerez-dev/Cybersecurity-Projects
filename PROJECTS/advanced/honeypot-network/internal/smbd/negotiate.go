/*
©AngelaMos | 2026
negotiate.go

SMB negotiate protocol handler for the honeypot

Parses NetBIOS session framing and detects SMB1/SMB2 negotiate
requests. Builds minimal negotiate responses that are valid enough
for network scanners like nmap and masscan to identify the service
as SMB. Only handles the initial negotiate exchange since full SMB
session setup requires 15+ message types.
*/

package smbd

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

var (
	smb2Magic = [4]byte{0xFE, 'S', 'M', 'B'}
	smb1Magic = [4]byte{0xFF, 'S', 'M', 'B'}
)

func readNBFrame(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}

	length := int(hdr[1])<<16 |
		int(hdr[2])<<8 |
		int(hdr[3])
	if length == 0 || length > 1<<20 {
		return nil, fmt.Errorf(
			"invalid frame length: %d", length,
		)
	}

	data := make([]byte, length)
	_, err := io.ReadFull(conn, data)
	return data, err
}

func writeNBFrame(
	conn net.Conn, data []byte,
) error {
	hdr := make([]byte, 4)
	hdr[1] = byte(len(data) >> 16)
	hdr[2] = byte(len(data) >> 8)
	hdr[3] = byte(len(data))

	_, err := conn.Write(append(hdr, data...))
	return err
}

func detectVersion(data []byte) int {
	if len(data) < 4 {
		return 0
	}

	if data[0] == smb2Magic[0] &&
		data[1] == smb2Magic[1] &&
		data[2] == smb2Magic[2] &&
		data[3] == smb2Magic[3] {
		return 2
	}

	if data[0] == smb1Magic[0] &&
		data[1] == smb1Magic[1] &&
		data[2] == smb1Magic[2] &&
		data[3] == smb1Magic[3] {
		return 1
	}

	return 0
}

func buildNegotiateResponse(version int) []byte {
	if version == 2 {
		return buildSMB2Response()
	}
	return buildSMB1Response()
}

func buildSMB2Response() []byte {
	resp := make([]byte, 64+65)

	copy(resp[0:4], smb2Magic[:])
	binary.LittleEndian.PutUint16(resp[4:6], 64)
	binary.LittleEndian.PutUint16(resp[14:16], 1)

	off := 64
	binary.LittleEndian.PutUint16(
		resp[off:off+2], 65,
	)
	binary.LittleEndian.PutUint16(
		resp[off+2:off+4], 1,
	)
	binary.LittleEndian.PutUint16(
		resp[off+4:off+6], 0x0210,
	)

	guid := [16]byte{
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c,
		0x0d, 0x0e, 0x0f, 0x10,
	}
	copy(resp[off+8:off+24], guid[:])

	binary.LittleEndian.PutUint32(
		resp[off+24:off+28], 7,
	)
	binary.LittleEndian.PutUint32(
		resp[off+28:off+32], 1<<20,
	)
	binary.LittleEndian.PutUint32(
		resp[off+32:off+36], 1<<20,
	)
	binary.LittleEndian.PutUint32(
		resp[off+36:off+40], 1<<20,
	)

	return resp
}

func buildSMB1Response() []byte {
	resp := make([]byte, 32+37)

	copy(resp[0:4], smb1Magic[:])
	resp[4] = 0x72
	resp[9] = 0x98
	binary.LittleEndian.PutUint16(
		resp[10:12], 0x4001,
	)

	off := 32
	resp[off] = 17
	resp[off+3] = 0x03
	binary.LittleEndian.PutUint16(
		resp[off+4:off+6], 1,
	)
	binary.LittleEndian.PutUint16(
		resp[off+6:off+8], 1,
	)
	binary.LittleEndian.PutUint32(
		resp[off+8:off+12], 1<<16,
	)
	binary.LittleEndian.PutUint32(
		resp[off+12:off+16], 1<<16,
	)

	return resp
}

func extractDialects(data []byte) []string {
	if len(data) < 72 {
		return nil
	}

	version := detectVersion(data)
	if version != 2 {
		return nil
	}

	off := 64
	if len(data) < off+36 {
		return nil
	}

	dialectCount := int(
		binary.LittleEndian.Uint16(data[off+2 : off+4]),
	)
	if dialectCount == 0 || dialectCount > 32 {
		return nil
	}

	dialects := make([]string, 0, dialectCount)
	dOff := off + 36

	for i := 0; i < dialectCount && dOff+2 <= len(data); i++ {
		d := binary.LittleEndian.Uint16(
			data[dOff : dOff+2],
		)
		dialects = append(
			dialects, fmt.Sprintf("0x%04x", d),
		)
		dOff += 2
	}

	return dialects
}
