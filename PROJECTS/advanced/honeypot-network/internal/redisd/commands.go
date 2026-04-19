/*
©AngelaMos | 2026
commands.go

Redis command handlers for the RESP protocol honeypot

Emulates enough Redis commands to engage automated scanners and
manual attackers. CONFIG SET and SLAVEOF commands are logged as
exploit attempts since they are commonly used for cryptominer
deployment and unauthorized replication attacks.
*/

package redisd

import (
	"fmt"
	"strings"
	"sync"

	"github.com/tidwall/redcon"
)

type safeStore struct {
	mu   sync.RWMutex
	data map[string]string
}

func newSafeStore() *safeStore {
	return &safeStore{data: make(map[string]string)}
}

func (s *safeStore) set(k, v string) {
	s.mu.Lock()
	s.data[k] = v
	s.mu.Unlock()
}

func (s *safeStore) get(k string) (string, bool) {
	s.mu.RLock()
	v, ok := s.data[k]
	s.mu.RUnlock()
	return v, ok
}

func (s *safeStore) size() int {
	s.mu.RLock()
	n := len(s.data)
	s.mu.RUnlock()
	return n
}

func (s *safeStore) flush() {
	s.mu.Lock()
	s.data = make(map[string]string)
	s.mu.Unlock()
}

func handleCommand(
	conn redcon.Conn, cmd redcon.Command,
	version string, keys *safeStore,
) string {
	name := strings.ToUpper(string(cmd.Args[0]))

	switch name {
	case "PING":
		if len(cmd.Args) > 1 {
			conn.WriteBulk(cmd.Args[1])
			return name
		}
		conn.WriteString("PONG")
		return name

	case "AUTH":
		conn.WriteError("ERR Client sent AUTH, but no password is set")
		return name

	case "INFO":
		conn.WriteBulkString(fakeInfo(version))
		return name

	case "CONFIG":
		return handleConfig(conn, cmd)

	case "SET":
		if len(cmd.Args) < 3 {
			conn.WriteError(
				"ERR wrong number of arguments for 'set' command",
			)
			return name
		}
		keys.set(string(cmd.Args[1]), string(cmd.Args[2]))
		conn.WriteString("OK")
		return name

	case "GET":
		if len(cmd.Args) < 2 {
			conn.WriteError(
				"ERR wrong number of arguments for 'get' command",
			)
			return name
		}
		val, ok := keys.get(string(cmd.Args[1]))
		if ok {
			conn.WriteBulkString(val)
		} else {
			conn.WriteNull()
		}
		return name

	case "KEYS":
		if len(cmd.Args) < 2 {
			conn.WriteError(
				"ERR wrong number of arguments for 'keys' command",
			)
			return name
		}
		conn.WriteArray(0)
		return name

	case "DBSIZE":
		conn.WriteInt(keys.size())
		return name

	case "COMMAND":
		conn.WriteArray(0)
		return name

	case "SELECT":
		conn.WriteString("OK")
		return name

	case "FLUSHALL", "FLUSHDB":
		keys.flush()
		conn.WriteString("OK")
		return name

	case "QUIT":
		conn.WriteString("OK")
		_ = conn.Close()
		return name

	case cmdSlaveOf, cmdReplicaOf:
		conn.WriteString("OK")
		return name

	case "MODULE":
		conn.WriteError(
			"ERR unknown command 'MODULE'",
		)
		return name

	case "EVAL", "EVALSHA":
		conn.WriteError(
			"NOSCRIPT No matching script",
		)
		return name

	case "DEBUG":
		conn.WriteError(
			"ERR DEBUG command not allowed",
		)
		return name

	case "CLUSTER":
		conn.WriteError(
			"ERR This instance has cluster support disabled",
		)
		return name

	default:
		conn.WriteError(
			fmt.Sprintf(
				"ERR unknown command '%s'",
				strings.ToLower(name),
			),
		)
		return name
	}
}

func handleConfig(
	conn redcon.Conn, cmd redcon.Command,
) string {
	if len(cmd.Args) < 2 {
		conn.WriteError(
			"ERR wrong number of arguments for 'config' command",
		)
		return "CONFIG"
	}

	sub := strings.ToUpper(string(cmd.Args[1]))

	switch sub {
	case "GET":
		if len(cmd.Args) < 3 {
			conn.WriteError(
				"ERR wrong number of arguments for 'config|get' command",
			)
			return "CONFIG GET"
		}
		param := strings.ToLower(string(cmd.Args[2]))
		switch param {
		case "dir":
			conn.WriteArray(2)
			conn.WriteBulkString("dir")
			conn.WriteBulkString("/var/lib/redis")
		case "dbfilename":
			conn.WriteArray(2)
			conn.WriteBulkString("dbfilename")
			conn.WriteBulkString("dump.rdb")
		case "save":
			conn.WriteArray(2)
			conn.WriteBulkString("save")
			conn.WriteBulkString("3600 1 300 100 60 10000")
		default:
			conn.WriteArray(0)
		}
		return "CONFIG GET"

	case "SET":
		conn.WriteString("OK")
		return cmdConfigSet

	case "RESETSTAT":
		conn.WriteString("OK")
		return "CONFIG RESETSTAT"

	default:
		conn.WriteError(
			fmt.Sprintf(
				"ERR Unknown subcommand or wrong number of arguments for 'config|%s' command",
				strings.ToLower(sub),
			),
		)
		return "CONFIG " + sub
	}
}

func fakeInfo(version string) string {
	return fmt.Sprintf(
		"# Server\r\n"+
			"redis_version:%s\r\n"+
			"redis_git_sha1:00000000\r\n"+
			"redis_git_dirty:0\r\n"+
			"redis_build_id:abc123def456\r\n"+
			"redis_mode:standalone\r\n"+
			"os:Linux 5.15.0-105-generic x86_64\r\n"+
			"arch_bits:64\r\n"+
			"multiplexing_api:epoll\r\n"+
			"gcc_version:11.4.0\r\n"+
			"process_id:1024\r\n"+
			"run_id:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\n"+
			"tcp_port:6379\r\n"+
			"uptime_in_seconds:1234567\r\n"+
			"uptime_in_days:14\r\n"+
			"hz:10\r\n\r\n"+
			"# Clients\r\n"+
			"connected_clients:1\r\n"+
			"blocked_clients:0\r\n\r\n"+
			"# Memory\r\n"+
			"used_memory:1048576\r\n"+
			"used_memory_human:1.00M\r\n"+
			"used_memory_rss:2097152\r\n"+
			"used_memory_peak:2097152\r\n"+
			"used_memory_peak_human:2.00M\r\n\r\n"+
			"# Keyspace\r\n"+
			"db0:keys=0,expires=0,avg_ttl=0\r\n",
		version,
	)
}
