/*
©AngelaMos | 2026
handler.go

MySQL wire protocol handler for the honeypot

Implements the MySQL client-server protocol at the packet level:
greeting handshake, authentication parsing, and query response
generation. Builds valid MySQL packets without external dependencies
to give full control over what gets logged and how the honeypot
responds to automated exploitation tools.
*/

package mysqld

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	comQuit      byte = 0x01
	comInitDB    byte = 0x02
	comQuery     byte = 0x03
	comFieldList byte = 0x04
	comPing      byte = 0x0e
)

const (
	clientProtocol41 uint32 = 1 << 9
	clientSecureConn uint32 = 1 << 15
	clientPluginAuth uint32 = 1 << 19
)

const statusAutocommit uint16 = 0x0002

func writePacket(
	conn net.Conn, seq byte, data []byte,
) error {
	header := make([]byte, 4)
	header[0] = byte(len(data))
	header[1] = byte(len(data) >> 8)
	header[2] = byte(len(data) >> 16)
	header[3] = seq

	_, err := conn.Write(append(header, data...))
	return err
}

func readPacket(
	conn net.Conn,
) (byte, []byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}

	length := int(header[0]) |
		int(header[1])<<8 |
		int(header[2])<<16
	seq := header[3]

	if length == 0 {
		return seq, nil, nil
	}

	if length > 1<<20 {
		return seq, nil, fmt.Errorf(
			"packet too large: %d", length,
		)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return seq, nil, err
	}

	return seq, payload, nil
}

func buildGreeting(
	version string, connID uint32,
) []byte {
	salt1 := []byte{
		0x52, 0x42, 0x33, 0x76,
		0x7a, 0x26, 0x47, 0x72,
	}
	salt2 := []byte{
		0x2b, 0x5a, 0x28, 0x40, 0x22, 0x37,
		0x71, 0x41, 0x2d, 0x64, 0x34, 0x62, 0x00,
	}
	pluginName := "mysql_native_password"

	caps := clientProtocol41 |
		clientSecureConn |
		clientPluginAuth

	var buf []byte
	buf = append(buf, 10)
	buf = append(buf, version...)
	buf = append(buf, 0)

	id := make([]byte, 4)
	binary.LittleEndian.PutUint32(id, connID)
	buf = append(buf, id...)

	buf = append(buf, salt1...)
	buf = append(buf, 0)

	lo := make([]byte, 2)
	binary.LittleEndian.PutUint16(
		lo, uint16(caps&0xFFFF),
	)
	buf = append(buf, lo...)

	buf = append(buf, 0x21)

	st := make([]byte, 2)
	binary.LittleEndian.PutUint16(st, statusAutocommit)
	buf = append(buf, st...)

	hi := make([]byte, 2)
	binary.LittleEndian.PutUint16(
		hi, uint16((caps>>16)&0xFFFF),
	)
	buf = append(buf, hi...)

	buf = append(buf, 21)
	buf = append(buf, make([]byte, 10)...)
	buf = append(buf, salt2...)
	buf = append(buf, pluginName...)
	buf = append(buf, 0)

	return buf
}

func parseAuthUsername(data []byte) string {
	if len(data) < 32 {
		return ""
	}

	rest := data[32:]
	for i, b := range rest {
		if b == 0 {
			return string(rest[:i])
		}
	}
	return string(rest)
}

func okPacket() []byte {
	return []byte{
		0x00,
		0x00,
		0x00,
		0x02, 0x00,
		0x00, 0x00,
	}
}

func errPacket(
	code uint16, state, msg string,
) []byte {
	var buf []byte
	buf = append(buf, 0xFF)

	ec := make([]byte, 2)
	binary.LittleEndian.PutUint16(ec, code)
	buf = append(buf, ec...)

	buf = append(buf, '#')

	padded := state
	if len(padded) > 5 {
		padded = padded[:5]
	}
	for len(padded) < 5 {
		padded += " "
	}
	buf = append(buf, padded...)
	buf = append(buf, msg...)

	return buf
}

func eofPacket() []byte {
	return []byte{0xFE, 0x00, 0x00, 0x02, 0x00}
}

func lenEncInt(n int) []byte {
	if n < 251 {
		return []byte{byte(n)}
	}
	if n < 1<<16 {
		b := make([]byte, 3)
		b[0] = 0xFC
		binary.LittleEndian.PutUint16(b[1:], uint16(n))
		return b
	}
	b := make([]byte, 4)
	b[0] = 0xFD
	b[1] = byte(n)
	b[2] = byte(n >> 8)
	b[3] = byte(n >> 16)
	return b
}

func lenEncString(s string) []byte {
	return append(lenEncInt(len(s)), s...)
}

func columnDef(name string) []byte {
	var buf []byte
	buf = append(buf, lenEncString("def")...)
	buf = append(buf, lenEncString("")...)
	buf = append(buf, lenEncString("")...)
	buf = append(buf, lenEncString("")...)
	buf = append(buf, lenEncString(name)...)
	buf = append(buf, lenEncString(name)...)
	buf = append(buf, 0x0C)
	buf = append(buf, 0x21, 0x00)
	buf = append(buf, 0x00, 0x01, 0x00, 0x00)
	buf = append(buf, 0xFD)
	buf = append(buf, 0x01, 0x00)
	buf = append(buf, 0x00)
	buf = append(buf, 0x00, 0x00)
	return buf
}

type queryResult struct {
	columns []string
	rows    [][]string
}

func handleQuery(query string) *queryResult {
	upper := strings.ToUpper(strings.TrimSpace(query))

	switch {
	case strings.HasPrefix(upper, "SELECT @@VERSION"):
		return &queryResult{
			columns: []string{"@@version_comment"},
			rows:    [][]string{{"(Ubuntu)"}},
		}

	case strings.HasPrefix(upper, "SELECT DATABASE"):
		return &queryResult{
			columns: []string{"database()"},
			rows:    [][]string{{"mysql"}},
		}

	case strings.HasPrefix(upper, "SELECT USER"):
		return &queryResult{
			columns: []string{"user()"},
			rows:    [][]string{{"root@localhost"}},
		}

	case upper == "SHOW DATABASES":
		return &queryResult{
			columns: []string{"Database"},
			rows: [][]string{
				{"information_schema"},
				{"mysql"},
				{"performance_schema"},
				{"sys"},
			},
		}

	case upper == "SHOW TABLES":
		return &queryResult{
			columns: []string{"Tables_in_mysql"},
			rows: [][]string{
				{"columns_priv"},
				{"db"},
				{"event"},
				{"func"},
				{"general_log"},
				{"help_category"},
				{"user"},
			},
		}

	case strings.Contains(upper, "INFORMATION_SCHEMA"):
		return &queryResult{
			columns: []string{"TABLE_NAME"},
			rows:    [][]string{},
		}

	case strings.HasPrefix(upper, "SELECT @@DATADIR"):
		return &queryResult{
			columns: []string{"@@datadir"},
			rows:    [][]string{{"/var/lib/mysql/"}},
		}

	case strings.HasPrefix(upper, "SELECT @@HOSTNAME"):
		return &queryResult{
			columns: []string{"@@hostname"},
			rows:    [][]string{{"ubuntu-server"}},
		}

	case strings.HasPrefix(upper, "SHOW VARIABLES"):
		return &queryResult{
			columns: []string{
				"Variable_name", "Value",
			},
			rows: [][]string{
				{"version", "5.7.42-0ubuntu0.18.04.1"},
				{"datadir", "/var/lib/mysql/"},
				{"hostname", "ubuntu-server"},
				{"port", "3306"},
			},
		}
	}

	return nil
}

func writeResultSet(
	conn net.Conn, seq byte, res *queryResult,
) error {
	seq++
	if err := writePacket(
		conn, seq, lenEncInt(len(res.columns)),
	); err != nil {
		return err
	}

	for _, col := range res.columns {
		seq++
		if err := writePacket(
			conn, seq, columnDef(col),
		); err != nil {
			return err
		}
	}

	seq++
	if err := writePacket(
		conn, seq, eofPacket(),
	); err != nil {
		return err
	}

	for _, row := range res.rows {
		seq++
		var rowBuf []byte
		for _, val := range row {
			rowBuf = append(
				rowBuf, lenEncString(val)...,
			)
		}
		if err := writePacket(
			conn, seq, rowBuf,
		); err != nil {
			return err
		}
	}

	seq++
	return writePacket(conn, seq, eofPacket())
}
