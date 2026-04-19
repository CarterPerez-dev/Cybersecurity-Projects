/*
©AngelaMos | 2026
commands.go

Fake command execution for the SSH honeypot shell

Dispatches typed commands to handlers that return realistic output
matching what an Ubuntu 22.04 server would produce. Unknown commands
return the standard bash error format. Commands like wget and curl
are logged but produce simulated network errors to prevent the
honeypot from making real outbound connections.
*/

package sshd

import (
	"fmt"
	"strings"
	"time"
)

type CommandContext struct {
	FS       *FakeFS
	Hostname string
	Username string
	CWD      string
}

func DispatchCommand(
	input string, ctx *CommandContext,
) string {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return ""
	}

	cmd := parts[0]
	args := parts[1:]

	switch cmd {
	case "id":
		return cmdID(ctx)
	case "whoami":
		return cmdWhoami(ctx)
	case "uname":
		return cmdUname(args)
	case "hostname":
		return ctx.Hostname + "\n"
	case "pwd":
		return ctx.CWD + "\n"
	case "ls":
		return cmdLS(args, ctx)
	case "cat":
		return cmdCat(args, ctx)
	case "echo":
		return strings.Join(args, " ") + "\n"
	case "ps":
		return cmdPS()
	case "w":
		return cmdW(ctx)
	case "uptime":
		return cmdUptime()
	case "free":
		return cmdFree()
	case "df":
		return cmdDF()
	case "ifconfig":
		return cmdIfconfig()
	case "ip":
		return cmdIP(args)
	case "netstat":
		return cmdNetstat()
	case "wget", "curl":
		return cmdDownload(cmd, args)
	case "cd":
		return cmdCD(args, ctx)
	case "history":
		return ""
	case "export":
		return ""
	case "unset":
		return ""
	case "env":
		return cmdEnv(ctx)
	case "which":
		return cmdWhich(args)
	case "type":
		return cmdType(args)
	case "nproc":
		return "2\n"
	case "arch":
		return "x86_64\n"
	case "date":
		return time.Now().UTC().Format(
			"Mon Jan  2 15:04:05 UTC 2006",
		) + "\n"
	case "exit", "logout", "quit":
		return ""
	default:
		return fmt.Sprintf(
			"bash: %s: command not found\n", cmd,
		)
	}
}

func cmdID(ctx *CommandContext) string {
	if ctx.Username == "root" {
		return "uid=0(root) gid=0(root) groups=0(root)\n"
	}
	return "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)\n"
}

func cmdWhoami(ctx *CommandContext) string {
	return ctx.Username + "\n"
}

func cmdUname(args []string) string {
	if len(args) == 0 {
		return "Linux\n"
	}

	for _, a := range args {
		if a == "-a" || a == "--all" {
			return "Linux ubuntu-server 5.15.0-105-generic " +
				"#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 " +
				"x86_64 x86_64 x86_64 GNU/Linux\n"
		}
		if a == "-r" {
			return "5.15.0-105-generic\n"
		}
		if a == "-n" {
			return "ubuntu-server\n"
		}
		if a == "-m" {
			return "x86_64\n"
		}
	}

	return "Linux\n"
}

func cmdLS(args []string, ctx *CommandContext) string {
	path := ctx.CWD
	long := false

	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "l") {
				long = true
			}
			continue
		}
		path = resolvePath(a, ctx.CWD)
	}

	if !ctx.FS.IsDir(path) {
		if ctx.FS.Exists(path) {
			parts := strings.Split(path, "/")
			name := parts[len(parts)-1]
			if long {
				return fmt.Sprintf(
					"-rw-r--r-- 1 root root 0 %s %s\n",
					time.Now().AddDate(0, 0, -7).Format("Jan  2 15:04"),
					name,
				)
			}
			return name + "\n"
		}
		return fmt.Sprintf(
			"ls: cannot access '%s': No such file or directory\n",
			path,
		)
	}

	if long {
		return ctx.FS.ListDir(path)
	}

	listing := ctx.FS.ListDir(path)
	if listing == "" {
		return ""
	}

	var names []string
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			names = append(names, fields[len(fields)-1])
		}
	}
	return strings.Join(names, "  ") + "\n"
}

func cmdCat(args []string, ctx *CommandContext) string {
	if len(args) == 0 {
		return ""
	}

	path := resolvePath(args[0], ctx.CWD)
	content, exists := ctx.FS.ReadFile(path)
	if !exists {
		return fmt.Sprintf(
			"cat: %s: No such file or directory\n", args[0],
		)
	}
	return content
}

func cmdPS() string {
	return "  PID TTY          TIME CMD\n" +
		"    1 ?        00:00:03 systemd\n" +
		"  412 ?        00:00:01 systemd-journal\n" +
		"  489 ?        00:00:00 sshd\n" +
		"  612 ?        00:00:00 cron\n" +
		"  718 ?        00:00:00 apache2\n" +
		"  721 ?        00:00:00 apache2\n" +
		"  722 ?        00:00:00 apache2\n" +
		" 1024 ?        00:00:00 mysqld\n" +
		" 2048 pts/0    00:00:00 bash\n" +
		" 2089 pts/0    00:00:00 ps\n"
}

func cmdW(ctx *CommandContext) string {
	now := time.Now().UTC()
	return fmt.Sprintf(
		" %s up 142 days,  3:27,  1 user,  load average: 0.08, 0.12, 0.09\n"+
			"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"+
			"%-8s pts/0    192.168.1.100    %s    0.00s  0.04s  0.00s w\n",
		now.Format("15:04:05"),
		ctx.Username,
		now.Add(-5*time.Minute).Format("15:04"),
	)
}

func cmdUptime() string {
	now := time.Now().UTC()
	return fmt.Sprintf(
		" %s up 142 days,  3:27,  1 user,  load average: 0.08, 0.12, 0.09\n",
		now.Format("15:04:05"),
	)
}

func cmdFree() string {
	return "               total        used        free      shared  buff/cache   available\n" +
		"Mem:         4028440     1156120     1245680       12340     1626640     2876340\n" +
		"Swap:        2097148           0     2097148\n"
}

func cmdDF() string {
	return "Filesystem     1K-blocks    Used Available Use% Mounted on\n" +
		"/dev/sda1       41251136 8234752  30897440  22% /\n" +
		"tmpfs            2014220       0   2014220   0% /dev/shm\n" +
		"tmpfs             402844    1124    401720   1% /run\n" +
		"tmpfs               5120       4      5116   1% /run/lock\n" +
		"/dev/sda15        106858    6186    100672   6% /boot/efi\n"
}

func cmdIfconfig() string {
	return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n" +
		"        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n" +
		"        inet6 fe80::a00:27ff:fe2a:1b3c  prefixlen 64  scopeid 0x20<link>\n" +
		"        ether 08:00:27:2a:1b:3c  txqueuelen 1000  (Ethernet)\n" +
		"        RX packets 524892  bytes 423871632 (423.8 MB)\n" +
		"        TX packets 213456  bytes 31245781 (31.2 MB)\n\n" +
		"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n" +
		"        inet 127.0.0.1  netmask 255.0.0.0\n" +
		"        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n" +
		"        loop  txqueuelen 1000  (Local Loopback)\n" +
		"        RX packets 1024  bytes 82432 (82.4 kB)\n" +
		"        TX packets 1024  bytes 82432 (82.4 kB)\n"
}

func cmdIP(args []string) string {
	if len(args) == 0 || args[0] == "addr" || args[0] == "a" {
		return "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n" +
			"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n" +
			"    inet 127.0.0.1/8 scope host lo\n" +
			"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n" +
			"    link/ether 08:00:27:2a:1b:3c brd ff:ff:ff:ff:ff:ff\n" +
			"    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic eth0\n"
	}
	if args[0] == "route" || args[0] == "r" {
		return "default via 10.0.2.1 dev eth0 proto dhcp metric 100\n" +
			"10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15 metric 100\n"
	}
	return ""
}

func cmdNetstat() string {
	return "Active Internet connections (servers and established)\n" +
		"Proto Recv-Q Send-Q Local Address           Foreign Address         State\n" +
		"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n" +
		"tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n" +
		"tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n" +
		"tcp6       0      0 :::22                   :::*                    LISTEN\n"
}

func cmdDownload(cmd string, args []string) string {
	if len(args) == 0 {
		return fmt.Sprintf(
			"%s: missing URL\nUsage: %s [OPTION]... [URL]...\n",
			cmd, cmd,
		)
	}

	url := args[len(args)-1]
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			url = a
			break
		}
	}

	if cmd == "wget" {
		return fmt.Sprintf(
			"--%s--  %s\nResolving failed: Temporary failure in name resolution.\n"+
				"wget: unable to resolve host address\n",
			time.Now().UTC().Format("2006-01-02 15:04:05"),
			url,
		)
	}

	return fmt.Sprintf(
		"curl: (6) Could not resolve host: %s\n",
		strings.TrimPrefix(
			strings.TrimPrefix(url, "https://"),
			"http://",
		),
	)
}

func cmdCD(args []string, ctx *CommandContext) string {
	if len(args) == 0 {
		ctx.CWD = "/root"
		return ""
	}

	target := resolvePath(args[0], ctx.CWD)
	if ctx.FS.IsDir(target) {
		ctx.CWD = target
		return ""
	}

	return fmt.Sprintf(
		"bash: cd: %s: No such file or directory\n", args[0],
	)
}

func cmdEnv(ctx *CommandContext) string {
	return fmt.Sprintf(
		"SHELL=/bin/bash\n"+
			"PWD=%s\n"+
			"LOGNAME=%s\n"+
			"HOME=/root\n"+
			"LANG=en_US.UTF-8\n"+
			"TERM=xterm-256color\n"+
			"USER=%s\n"+
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"+
			"MAIL=/var/mail/%s\n"+
			"HOSTNAME=%s\n",
		ctx.CWD, ctx.Username, ctx.Username,
		ctx.Username, ctx.Hostname,
	)
}

func cmdWhich(args []string) string {
	if len(args) == 0 {
		return ""
	}

	known := map[string]string{
		"ls": "/usr/bin/ls", "cat": "/usr/bin/cat",
		"grep": "/usr/bin/grep", "ps": "/usr/bin/ps",
		"bash": "/usr/bin/bash", "ssh": "/usr/bin/ssh",
		"wget": "/usr/bin/wget", "curl": "/usr/bin/curl",
		"python3": "/usr/bin/python3", "perl": "/usr/bin/perl",
		"awk": "/usr/bin/awk", "sed": "/usr/bin/sed",
	}

	if path, ok := known[args[0]]; ok {
		return path + "\n"
	}
	return fmt.Sprintf(
		"which: no %s in (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)\n",
		args[0],
	)
}

func cmdType(args []string) string {
	if len(args) == 0 {
		return ""
	}

	builtins := map[string]bool{
		"cd": true, "echo": true, "export": true,
		"exit": true, "history": true, "type": true,
	}

	if builtins[args[0]] {
		return fmt.Sprintf(
			"%s is a shell builtin\n", args[0],
		)
	}

	result := cmdWhich(args)
	if strings.HasPrefix(result, "/") {
		return fmt.Sprintf(
			"%s is %s",
			args[0], strings.TrimSpace(result),
		) + "\n"
	}
	return fmt.Sprintf(
		"bash: type: %s: not found\n", args[0],
	)
}

func resolvePath(path, cwd string) string {
	if strings.HasPrefix(path, "/") {
		return cleanPath(path)
	}
	if path == "~" || path == "" {
		return "/root"
	}
	if strings.HasPrefix(path, "~/") {
		return cleanPath("/root/" + path[2:])
	}
	if path == ".." {
		parts := strings.Split(cwd, "/")
		if len(parts) > 1 {
			return "/" + strings.Join(parts[1:len(parts)-1], "/")
		}
		return "/"
	}
	if path == "." {
		return cwd
	}
	if cwd == "/" {
		return "/" + path
	}
	return cleanPath(cwd + "/" + path)
}

func cleanPath(path string) string {
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
