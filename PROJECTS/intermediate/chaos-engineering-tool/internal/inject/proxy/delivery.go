// ©AngelaMos | 2026
// delivery.go

package proxy

import (
	"fmt"
	"net"
)

func (p *Proxy) WatchSources(addresses []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(addresses) == 0 {
		return fmt.Errorf(
			"the proxy has no target network addresses to observe",
		)
	}
	for _, address := range addresses {
		ip := net.ParseIP(address)
		if ip == nil {
			return fmt.Errorf("invalid target address %q", address)
		}
		p.sources[ip.String()] = 0
		p.faultSources[ip.String()] = 0
	}
	return nil
}

func (p *Proxy) countSource(address net.Addr) {
	peer, ok := address.(*net.TCPAddr)
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := peer.IP.String()
	if _, watched := p.sources[key]; !watched {
		return
	}
	p.sources[key]++
	if p.state.Load().fault.Kind != PassThrough {
		p.faultSources[key]++
	}
}

func (p *Proxy) TargetConnections() (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var total int64
	for _, count := range p.sources {
		total += count
	}
	return total, nil
}

func (p *Proxy) FaultConnections() (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var total int64
	for _, count := range p.faultSources {
		total += count
	}
	return total, nil
}
