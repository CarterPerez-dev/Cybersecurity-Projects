/*
©AngelaMos | 2026
handler.go

FTP command handler and data channel management for the honeypot

Implements the FTP control protocol with USER/PASS authentication,
PASV data channels for directory listings, and STOR upload capture
limited to 1MB per file. Presents a realistic ProFTPD environment
with fake directory listings that mirror an Ubuntu server layout.
*/

package ftpd

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	stateInit = iota
	stateUser
	stateAuth
)

type ftpConn struct {
	ctrl       net.Conn
	reader     *bufio.Reader
	state      int
	username   string
	cwd        string
	binary     bool
	dataListen net.Listener
}

func newFTPConn(conn net.Conn) *ftpConn {
	return &ftpConn{
		ctrl:   conn,
		reader: bufio.NewReader(conn),
		cwd:    "/",
	}
}

func (f *ftpConn) reply(code int, msg string) {
	fmt.Fprintf(f.ctrl, "%d %s\r\n", code, msg)
}

func (f *ftpConn) readLine() (string, string, error) {
	line, err := f.reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}

	line = strings.TrimRight(line, "\r\n")
	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToUpper(parts[0])

	arg := ""
	if len(parts) > 1 {
		arg = parts[1]
	}

	return cmd, arg, nil
}

func (f *ftpConn) close() {
	if f.dataListen != nil {
		_ = f.dataListen.Close()
	}
}

type cmdResult struct {
	cmd      string
	arg      string
	quit     bool
	password string
	upload   []byte
	filename string
}

func (f *ftpConn) dispatch(
	cmd, arg string,
) cmdResult {
	res := cmdResult{cmd: cmd, arg: arg}

	switch cmd {
	case "USER":
		f.username = arg
		f.state = stateUser
		f.reply(
			331, "Password required for "+arg,
		)

	case "PASS":
		f.state = stateAuth
		f.reply(
			230, "User "+f.username+" logged in",
		)
		res.password = arg

	case "SYST":
		f.reply(215, "UNIX Type: L8")

	case "FEAT":
		fmt.Fprintf(
			f.ctrl,
			"211-Features:\r\n"+
				" PASV\r\n"+
				" UTF8\r\n"+
				" SIZE\r\n"+
				"211 End\r\n",
		)

	case "PWD", "XPWD":
		f.reply(
			257,
			fmt.Sprintf(`"%s"`, f.cwd),
		)

	case "CWD", "XCWD":
		target := resolveFTPPath(arg, f.cwd)
		f.cwd = target
		f.reply(250, "CWD command successful")

	case "CDUP":
		f.cwd = parentFTPPath(f.cwd)
		f.reply(250, "CWD command successful")

	case "TYPE":
		f.binary = strings.ToUpper(arg) == "I"
		f.reply(200, "Type set")

	case "PASV":
		f.openPASV()

	case "LIST", "NLST":
		f.sendListing()

	case "RETR":
		if f.dataListen != nil {
			_ = f.dataListen.Close()
			f.dataListen = nil
		}
		f.reply(
			550,
			arg+": No such file or directory",
		)

	case "STOR":
		data := f.recvUpload()
		if data != nil {
			res.upload = data
			res.filename = arg
		}

	case "SIZE":
		f.reply(550, arg+": No such file")

	case "MDTM":
		f.reply(550, arg+": No such file")

	case "MKD", "XMKD":
		f.reply(
			257,
			fmt.Sprintf(`"%s" created`, arg),
		)

	case "RMD", "XRMD", "DELE":
		f.reply(250, "OK")

	case "RNFR":
		f.reply(350, "Awaiting new name")

	case "RNTO":
		f.reply(250, "Rename successful")

	case "NOOP":
		f.reply(200, "OK")

	case "HELP":
		f.reply(214, "No help available")

	case "QUIT":
		f.reply(221, "Goodbye")
		res.quit = true

	default:
		f.reply(502, "Command not implemented")
	}

	return res
}

func (f *ftpConn) openPASV() {
	if f.dataListen != nil {
		_ = f.dataListen.Close()
	}

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		f.reply(425, "Cannot open data connection")
		return
	}
	f.dataListen = l

	tcpAddr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		f.reply(425, "Cannot open data connection")
		return
	}
	port := tcpAddr.Port
	p1 := port / 256
	p2 := port % 256

	localAddr, ok := f.ctrl.LocalAddr().(*net.TCPAddr)
	if !ok {
		f.reply(425, "Cannot open data connection")
		return
	}
	ip := localAddr.IP.To4()
	if ip == nil {
		ip = net.ParseIP("127.0.0.1").To4()
	}

	f.reply(227, fmt.Sprintf(
		"Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
		ip[0], ip[1], ip[2], ip[3], p1, p2,
	))
}

func (f *ftpConn) acceptData() net.Conn {
	if f.dataListen == nil {
		return nil
	}
	defer func() {
		_ = f.dataListen.Close()
		f.dataListen = nil
	}()

	tcpL, ok := f.dataListen.(*net.TCPListener)
	if !ok {
		return nil
	}
	_ = tcpL.SetDeadline(
		time.Now().Add(10 * time.Second),
	)

	dc, err := f.dataListen.Accept()
	if err != nil {
		return nil
	}
	return dc
}

func (f *ftpConn) sendListing() {
	if f.dataListen == nil {
		f.reply(425, "Use PASV first")
		return
	}

	f.reply(150, "Opening data connection")

	dc := f.acceptData()
	if dc == nil {
		f.reply(
			425, "Cannot open data connection",
		)
		return
	}

	_, _ = fmt.Fprint(dc, fakeDirListing(f.cwd))
	_ = dc.Close()

	f.reply(226, "Transfer complete")
}

func (f *ftpConn) recvUpload() []byte {
	if f.dataListen == nil {
		f.reply(425, "Use PASV first")
		return nil
	}

	f.reply(150, "Opening data connection")

	dc := f.acceptData()
	if dc == nil {
		f.reply(
			425, "Cannot open data connection",
		)
		return nil
	}

	data, _ := io.ReadAll(
		io.LimitReader(dc, 1<<20),
	)
	_ = dc.Close()

	f.reply(226, "Transfer complete")
	return data
}

func fakeDirListing(cwd string) string {
	now := time.Now()
	month := now.AddDate(0, -1, 0).Format("Jan 02 15:04")
	old := now.AddDate(0, -6, 0).Format("Jan 02 15:04")

	lines := []string{
		fmt.Sprintf(
			"drwxr-xr-x 2 root root 4096 %s .",
			month,
		),
		fmt.Sprintf(
			"drwxr-xr-x 3 root root 4096 %s ..",
			month,
		),
	}

	if cwd == "/" {
		lines = append(lines,
			fmt.Sprintf(
				"drwxr-xr-x 2 root root 4096 %s bin",
				month,
			),
			fmt.Sprintf(
				"drwxr-xr-x 5 root root 4096 %s etc",
				month,
			),
			fmt.Sprintf(
				"drwxr-xr-x 3 root root 4096 %s home",
				month,
			),
			fmt.Sprintf(
				"drwxr-xr-x 2 root root 4096 %s tmp",
				month,
			),
			fmt.Sprintf(
				"drwxr-xr-x 8 root root 4096 %s var",
				month,
			),
			fmt.Sprintf(
				"-rw-r--r-- 1 root root  220 %s .bashrc",
				old,
			),
		)
	}

	return strings.Join(lines, "\r\n") + "\r\n"
}

func resolveFTPPath(path, cwd string) string {
	if strings.HasPrefix(path, "/") {
		return cleanFTPPath(path)
	}
	if cwd == "/" {
		return cleanFTPPath("/" + path)
	}
	return cleanFTPPath(cwd + "/" + path)
}

func parentFTPPath(path string) string {
	if path == "/" {
		return "/"
	}
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return "/"
	}
	return strings.Join(parts[:len(parts)-1], "/")
}

func cleanFTPPath(path string) string {
	parts := strings.Split(path, "/")
	var clean []string
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			if len(clean) > 0 {
				clean = clean[:len(clean)-1]
			}
			continue
		}
		clean = append(clean, p)
	}
	if len(clean) == 0 {
		return "/"
	}
	return "/" + strings.Join(clean, "/")
}
