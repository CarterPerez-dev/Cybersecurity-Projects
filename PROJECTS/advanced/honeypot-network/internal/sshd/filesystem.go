/*
©AngelaMos | 2026
filesystem.go

In-memory fake filesystem for the SSH shell environment

Presents a realistic Ubuntu server filesystem with populated
/etc, /proc, /var, /home directories. Each file has plausible
contents that engaged attackers would expect to see after
compromising a Linux host.
*/

package sshd

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type fileEntry struct {
	name    string
	isDir   bool
	content string
	mode    string
}

type FakeFS struct {
	hostname string
	files    map[string]*fileEntry
}

func NewFakeFS(hostname string) *FakeFS {
	fs := &FakeFS{
		hostname: hostname,
		files:    make(map[string]*fileEntry),
	}
	fs.populate()
	return fs
}

func (fs *FakeFS) populate() {
	dirs := []string{
		"/", "/bin", "/boot", "/dev", "/etc",
		"/etc/ssh", "/etc/cron.d", "/etc/default",
		"/home", "/home/admin", "/lib", "/lib64",
		"/media", "/mnt", "/opt", "/proc",
		"/root", "/run", "/sbin", "/srv",
		"/sys", "/tmp", "/usr", "/usr/bin",
		"/usr/lib", "/usr/local", "/usr/sbin",
		"/var", "/var/log", "/var/lib", "/var/tmp",
		"/var/run", "/var/spool",
	}

	for _, d := range dirs {
		fs.files[d] = &fileEntry{
			name:  d,
			isDir: true,
			mode:  "drwxr-xr-x",
		}
	}

	fs.files["/etc/hostname"] = &fileEntry{
		name:    "hostname",
		content: fs.hostname + "\n",
		mode:    "-rw-r--r--",
	}

	fs.files["/etc/passwd"] = &fileEntry{
		name: "passwd",
		content: "root:x:0:0:root:/root:/bin/bash\n" +
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
			"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n" +
			"sys:x:3:3:sys:/dev:/usr/sbin/nologin\n" +
			"sync:x:4:65534:sync:/bin:/bin/sync\n" +
			"games:x:5:60:games:/usr/games:/usr/sbin/nologin\n" +
			"man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n" +
			"lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n" +
			"mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n" +
			"news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n" +
			"uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n" +
			"proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n" +
			"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n" +
			"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n" +
			"sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n" +
			"admin:x:1000:1000:admin:/home/admin:/bin/bash\n",
		mode: "-rw-r--r--",
	}

	fs.files["/etc/shadow"] = &fileEntry{
		name:    "shadow",
		content: "",
		mode:    "-rw-r-----",
	}

	fs.files["/etc/os-release"] = &fileEntry{
		name: "os-release",
		content: "PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n" +
			"NAME=\"Ubuntu\"\n" +
			"VERSION_ID=\"22.04\"\n" +
			"VERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\n" +
			"VERSION_CODENAME=jammy\n" +
			"ID=ubuntu\n" +
			"ID_LIKE=debian\n",
		mode: "-rw-r--r--",
	}

	fs.files["/etc/issue"] = &fileEntry{
		name:    "issue",
		content: "Ubuntu 22.04.4 LTS \\n \\l\n\n",
		mode:    "-rw-r--r--",
	}

	fs.files["/proc/version"] = &fileEntry{
		name: "version",
		content: "Linux version 5.15.0-105-generic " +
			"(buildd@lcy02-amd64-032) " +
			"(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, " +
			"GNU ld (GNU Binutils for Ubuntu) 2.38) " +
			"#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024\n",
		mode: "-r--r--r--",
	}

	fs.files["/proc/cpuinfo"] = &fileEntry{
		name: "cpuinfo",
		content: "processor\t: 0\n" +
			"vendor_id\t: GenuineIntel\n" +
			"cpu family\t: 6\n" +
			"model\t\t: 85\n" +
			"model name\t: Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz\n" +
			"stepping\t: 4\n" +
			"microcode\t: 0x2007006\n" +
			"cpu MHz\t\t: 2500.000\n" +
			"cache size\t: 33792 KB\n" +
			"physical id\t: 0\n" +
			"siblings\t: 2\n" +
			"core id\t\t: 0\n" +
			"cpu cores\t: 2\n" +
			"bogomips\t: 5000.00\n" +
			"flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor\n\n",
		mode: "-r--r--r--",
	}

	fs.files["/proc/meminfo"] = &fileEntry{
		name: "meminfo",
		content: "MemTotal:        4028440 kB\n" +
			"MemFree:         1245680 kB\n" +
			"MemAvailable:    2876340 kB\n" +
			"Buffers:          186420 kB\n" +
			"Cached:          1580240 kB\n" +
			"SwapCached:            0 kB\n" +
			"SwapTotal:       2097148 kB\n" +
			"SwapFree:        2097148 kB\n",
		mode: "-r--r--r--",
	}

	fs.files["/etc/ssh/sshd_config"] = &fileEntry{
		name: "sshd_config",
		content: "Port 22\n" +
			"PermitRootLogin yes\n" +
			"PubkeyAuthentication yes\n" +
			"PasswordAuthentication yes\n" +
			"UsePAM yes\n" +
			"X11Forwarding yes\n" +
			"PrintMotd no\n" +
			"AcceptEnv LANG LC_*\n" +
			"Subsystem\tsftp\t/usr/lib/openssh/sftp-server\n",
		mode: "-rw-r--r--",
	}
}

func (fs *FakeFS) ReadFile(path string) (string, bool) {
	entry, exists := fs.files[path]
	if !exists || entry.isDir {
		return "", false
	}
	return entry.content, true
}

func (fs *FakeFS) IsDir(path string) bool {
	entry, exists := fs.files[path]
	return exists && entry.isDir
}

func (fs *FakeFS) Exists(path string) bool {
	_, exists := fs.files[path]
	return exists
}

func (fs *FakeFS) ListDir(path string) string {
	if !fs.IsDir(path) {
		return ""
	}

	prefix := path
	if prefix != "/" {
		prefix += "/"
	}

	type namedEntry struct {
		name      string
		formatted string
	}

	var collected []namedEntry
	seen := make(map[string]bool)

	for p, entry := range fs.files {
		if p == path {
			continue
		}

		if !strings.HasPrefix(p, prefix) {
			continue
		}

		rest := strings.TrimPrefix(p, prefix)
		parts := strings.SplitN(rest, "/", 2)
		name := parts[0]

		if seen[name] || len(parts) != 1 {
			continue
		}
		seen[name] = true

		var line string
		if entry.isDir {
			line = fmt.Sprintf(
				"%s 2 root root 4096 %s %s",
				entry.mode,
				time.Now().AddDate(0, -1, 0).Format("Jan  2 15:04"),
				name,
			)
		} else {
			line = fmt.Sprintf(
				"%s 1 root root %4d %s %s",
				entry.mode,
				len(entry.content),
				time.Now().AddDate(0, 0, -7).Format("Jan  2 15:04"),
				name,
			)
		}
		collected = append(collected, namedEntry{name: name, formatted: line})
	}

	if len(collected) == 0 {
		return ""
	}

	sort.Slice(collected, func(i, j int) bool {
		return collected[i].name < collected[j].name
	})

	entries := make([]string, len(collected))
	for i, ne := range collected {
		entries[i] = ne.formatted
	}

	return fmt.Sprintf(
		"total %d\n%s\n",
		len(entries)*4,
		strings.Join(entries, "\n"),
	)
}
