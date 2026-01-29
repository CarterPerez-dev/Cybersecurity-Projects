/*
CarterPerez-dev | 2026
compose.go
*/

package parser

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type ComposeFile struct {
	Path     string
	Root     *yaml.Node
	Version  string
	Services map[string]*Service
	Networks map[string]*Network
	Volumes  map[string]*Volume
	Secrets  map[string]*Secret
	Configs  map[string]*Config
}

type Service struct {
	Name        string
	Node        *yaml.Node
	Line        int
	Image       string
	Build       *BuildConfig
	Ports       []PortMapping
	Volumes     []VolumeMount
	Environment map[string]EnvVar
	CapAdd      []string
	CapDrop     []string
	Privileged  bool
	ReadOnly    bool
	User        string
	NetworkMode string
	PidMode     string
	IpcMode     string
	SecurityOpt []string
	Deploy      *DeployConfig
	DependsOn   []string
	Healthcheck *HealthcheckConfig
}

type BuildConfig struct {
	Context    string
	Dockerfile string
	Args       map[string]string
	Target     string
	Line       int
}

type PortMapping struct {
	HostIP        string
	HostPort      string
	ContainerPort string
	Protocol      string
	Line          int
}

type VolumeMount struct {
	Source   string
	Target   string
	Type     string
	ReadOnly bool
	Line     int
}

type EnvVar struct {
	Name  string
	Value string
	Line  int
}

type DeployConfig struct {
	Replicas  int
	Resources *ResourceConfig
	Line      int
}

type ResourceConfig struct {
	Limits       *ResourceLimits
	Reservations *ResourceLimits
}

type ResourceLimits struct {
	CPUs   string
	Memory string
	Pids   int
}

type HealthcheckConfig struct {
	Test        []string
	Interval    string
	Timeout     string
	Retries     int
	StartPeriod string
	Disable     bool
	Line        int
}

type Network struct {
	Name     string
	Driver   string
	External bool
	Line     int
}

type Volume struct {
	Name     string
	Driver   string
	External bool
	Line     int
}

type Secret struct {
	Name     string
	File     string
	External bool
	Line     int
}

type Config struct {
	Name     string
	File     string
	External bool
	Line     int
}

func ParseComposeFile(path string) (*ComposeFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading compose file: %w", err)
	}

	return ParseComposeBytes(path, data)
}

func ParseComposeBytes(path string, data []byte) (*ComposeFile, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parsing yaml: %w", err)
	}

	cf := &ComposeFile{
		Path:     path,
		Root:     &root,
		Services: make(map[string]*Service),
		Networks: make(map[string]*Network),
		Volumes:  make(map[string]*Volume),
		Secrets:  make(map[string]*Secret),
		Configs:  make(map[string]*Config),
	}

	cf.extract()

	return cf, nil
}

func (cf *ComposeFile) extract() {
	if cf.Root.Kind == yaml.DocumentNode && len(cf.Root.Content) > 0 {
		cf.extractFromMapping(cf.Root.Content[0])
	} else if cf.Root.Kind == yaml.MappingNode {
		cf.extractFromMapping(cf.Root)
	}
}

func (cf *ComposeFile) extractFromMapping(node *yaml.Node) {
	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		key := node.Content[i].Value
		value := node.Content[i+1]

		switch key {
		case "version":
			cf.Version = value.Value
		case "services":
			cf.extractServices(value)
		case "networks":
			cf.extractNetworks(value)
		case "volumes":
			cf.extractVolumes(value)
		case "secrets":
			cf.extractSecrets(value)
		case "configs":
			cf.extractConfigs(value)
		}
	}
}

func (cf *ComposeFile) extractServices(node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		name := node.Content[i].Value
		serviceNode := node.Content[i+1]

		service := cf.parseService(name, serviceNode)
		cf.Services[name] = service
	}
}

func (cf *ComposeFile) parseService(name string, node *yaml.Node) *Service {
	svc := &Service{
		Name:        name,
		Node:        node,
		Line:        node.Line,
		Environment: make(map[string]EnvVar),
	}

	if node.Kind != yaml.MappingNode {
		return svc
	}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		key := node.Content[i].Value
		value := node.Content[i+1]

		switch key {
		case "image":
			svc.Image = value.Value
		case "build":
			svc.Build = cf.parseBuildConfig(value)
		case "ports":
			svc.Ports = cf.parsePorts(value)
		case "volumes":
			svc.Volumes = cf.parseVolumeMounts(value)
		case "environment":
			svc.Environment = cf.parseEnvironment(value)
		case "cap_add":
			svc.CapAdd = cf.parseStringList(value)
		case "cap_drop":
			svc.CapDrop = cf.parseStringList(value)
		case "privileged":
			svc.Privileged = value.Value == "true"
		case "read_only":
			svc.ReadOnly = value.Value == "true"
		case "user":
			svc.User = value.Value
		case "network_mode":
			svc.NetworkMode = value.Value
		case "pid":
			svc.PidMode = value.Value
		case "ipc":
			svc.IpcMode = value.Value
		case "security_opt":
			svc.SecurityOpt = cf.parseStringList(value)
		case "deploy":
			svc.Deploy = cf.parseDeployConfig(value)
		case "depends_on":
			svc.DependsOn = cf.parseDependsOn(value)
		case "healthcheck":
			svc.Healthcheck = cf.parseHealthcheck(value)
		}
	}

	return svc
}

func (cf *ComposeFile) parseBuildConfig(node *yaml.Node) *BuildConfig {
	bc := &BuildConfig{Line: node.Line}

	if node.Kind == yaml.ScalarNode {
		bc.Context = node.Value
		return bc
	}

	if node.Kind != yaml.MappingNode {
		return bc
	}

	bc.Args = make(map[string]string)

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		key := node.Content[i].Value
		value := node.Content[i+1]

		switch key {
		case "context":
			bc.Context = value.Value
		case "dockerfile":
			bc.Dockerfile = value.Value
		case "target":
			bc.Target = value.Value
		case "args":
			bc.Args = cf.parseStringMap(value)
		}
	}

	return bc
}

func (cf *ComposeFile) parsePorts(node *yaml.Node) []PortMapping {
	var ports []PortMapping

	if node.Kind != yaml.SequenceNode {
		return ports
	}

	for _, item := range node.Content {
		pm := PortMapping{Line: item.Line}

		switch item.Kind {
		case yaml.ScalarNode:
			pm = cf.parsePortString(item.Value, item.Line)
		case yaml.MappingNode:
			pm = cf.parsePortMapping(item)
		}

		ports = append(ports, pm)
	}

	return ports
}

func (cf *ComposeFile) parsePortString(s string, line int) PortMapping {
	pm := PortMapping{Line: line, Protocol: "tcp"}

	if idx := strings.LastIndex(s, "/"); idx != -1 {
		pm.Protocol = s[idx+1:]
		s = s[:idx]
	}

	parts := strings.Split(s, ":")

	switch len(parts) {
	case 1:
		pm.ContainerPort = parts[0]
	case 2:
		pm.HostPort = parts[0]
		pm.ContainerPort = parts[1]
	case 3:
		pm.HostIP = parts[0]
		pm.HostPort = parts[1]
		pm.ContainerPort = parts[2]
	}

	return pm
}

func (cf *ComposeFile) parsePortMapping(node *yaml.Node) PortMapping {
	pm := PortMapping{Line: node.Line, Protocol: "tcp"}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		key := node.Content[i].Value
		value := node.Content[i+1].Value

		switch key {
		case "target":
			pm.ContainerPort = value
		case "published":
			pm.HostPort = value
		case "host_ip":
			pm.HostIP = value
		case "protocol":
			pm.Protocol = value
		}
	}

	return pm
}

func (cf *ComposeFile) parseVolumeMounts(node *yaml.Node) []VolumeMount {
	var mounts []VolumeMount

	if node.Kind != yaml.SequenceNode {
		return mounts
	}

	for _, item := range node.Content {
		vm := VolumeMount{Line: item.Line}

		switch item.Kind {
		case yaml.ScalarNode:
			vm = cf.parseVolumeString(item.Value, item.Line)
		case yaml.MappingNode:
			vm = cf.parseVolumeMountMapping(item)
		}

		mounts = append(mounts, vm)
	}

	return mounts
}

func (cf *ComposeFile) parseVolumeString(s string, line int) VolumeMount {
	vm := VolumeMount{Line: line, Type: "bind"}

	parts := strings.Split(s, ":")

	switch len(parts) {
	case 1:
		vm.Target = parts[0]
		vm.Type = "volume"
	case 2:
		vm.Source = parts[0]
		vm.Target = parts[1]
	case 3:
		vm.Source = parts[0]
		vm.Target = parts[1]
		if parts[2] == "ro" {
			vm.ReadOnly = true
		}
	}

	if strings.HasPrefix(vm.Source, "/") ||
		strings.HasPrefix(vm.Source, ".") {
		vm.Type = "bind"
	} else if vm.Source != "" {
		vm.Type = "volume"
	}

	return vm
}

func (cf *ComposeFile) parseVolumeMountMapping(node *yaml.Node) VolumeMount {
	vm := VolumeMount{Line: node.Line}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		key := node.Content[i].Value
		value := node.Content[i+1]

		switch key {
		case "type":
			vm.Type = value.Value
		case "source":
			vm.Source = value.Value
		case "target":
			vm.Target = value.Value
		case "read_only":
			vm.ReadOnly = value.Value == "true"
		}
	}

	return vm
}

func (cf *ComposeFile) parseEnvironment(node *yaml.Node) map[string]EnvVar {
	env := make(map[string]EnvVar)

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 >= len(node.Content) {
				break
			}
			key := node.Content[i]
			value := node.Content[i+1]
			env[key.Value] = EnvVar{
				Name:  key.Value,
				Value: value.Value,
				Line:  key.Line,
			}
		}
	} else if node.Kind == yaml.SequenceNode {
		for _, item := range node.Content {
			parts := strings.SplitN(item.Value, "=", 2)
			name := parts[0]
			value := ""
			if len(parts) > 1 {
				value = parts[1]
			}
			env[name] = EnvVar{
				Name:  name,
				Value: value,
				Line:  item.Line,
			}
		}
	}

	return env
}

func (cf *ComposeFile) parseDeployConfig(node *yaml.Node) *DeployConfig {
	dc := &DeployConfig{Line: node.Line}

	if node.Kind != yaml.MappingNode {
		return dc
	}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		key := node.Content[i].Value
		value := node.Content[i+1]

		switch key {
		case "replicas":
			dc.Replicas, _ = strconv.Atoi(value.Value)
		case "resources":
			dc.Resources = cf.parseResourceConfig(value)
		}
	}

	return dc
}

func (cf *ComposeFile) parseResourceConfig(node *yaml.Node) *ResourceConfig {
	rc := &ResourceConfig{}

	if node.Kind != yaml.MappingNode {
		return rc
	}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		key := node.Content[i].Value
		value := node.Content[i+1]

		switch key {
		case "limits":
			rc.Limits = cf.parseResourceLimits(value)
		case "reservations":
			rc.Reservations = cf.parseResourceLimits(value)
		}
	}

	return rc
}

func (cf *ComposeFile) parseResourceLimits(node *yaml.Node) *ResourceLimits {
	rl := &ResourceLimits{}

	if node.Kind != yaml.MappingNode {
		return rl
	}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		key := node.Content[i].Value
		value := node.Content[i+1]

		switch key {
		case "cpus":
			rl.CPUs = value.Value
		case "memory":
			rl.Memory = value.Value
		case "pids":
			rl.Pids, _ = strconv.Atoi(value.Value)
		}
	}

	return rl
}

func (cf *ComposeFile) parseHealthcheck(node *yaml.Node) *HealthcheckConfig {
	hc := &HealthcheckConfig{Line: node.Line}

	if node.Kind != yaml.MappingNode {
		return hc
	}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		key := node.Content[i].Value
		value := node.Content[i+1]

		switch key {
		case "test":
			hc.Test = cf.parseStringList(value)
		case "interval":
			hc.Interval = value.Value
		case "timeout":
			hc.Timeout = value.Value
		case "retries":
			hc.Retries, _ = strconv.Atoi(value.Value)
		case "start_period":
			hc.StartPeriod = value.Value
		case "disable":
			hc.Disable = value.Value == "true"
		}
	}

	return hc
}

func (cf *ComposeFile) parseStringList(node *yaml.Node) []string {
	var result []string

	if node.Kind == yaml.ScalarNode {
		return []string{node.Value}
	}

	if node.Kind != yaml.SequenceNode {
		return result
	}

	for _, item := range node.Content {
		result = append(result, item.Value)
	}

	return result
}

func (cf *ComposeFile) parseStringMap(node *yaml.Node) map[string]string {
	result := make(map[string]string)

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 >= len(node.Content) {
				break
			}
			result[node.Content[i].Value] = node.Content[i+1].Value
		}
	} else if node.Kind == yaml.SequenceNode {
		for _, item := range node.Content {
			parts := strings.SplitN(item.Value, "=", 2)
			if len(parts) == 2 {
				result[parts[0]] = parts[1]
			}
		}
	}

	return result
}

func (cf *ComposeFile) parseDependsOn(node *yaml.Node) []string {
	if node.Kind == yaml.SequenceNode {
		return cf.parseStringList(node)
	}

	if node.Kind == yaml.MappingNode {
		var deps []string
		for i := 0; i < len(node.Content); i += 2 {
			deps = append(deps, node.Content[i].Value)
		}
		return deps
	}

	return nil
}

func (cf *ComposeFile) extractNetworks(node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		name := node.Content[i].Value
		netNode := node.Content[i+1]

		net := &Network{Name: name, Line: netNode.Line}

		if netNode.Kind == yaml.MappingNode {
			for j := 0; j < len(netNode.Content); j += 2 {
				if j+1 >= len(netNode.Content) {
					break
				}
				key := netNode.Content[j].Value
				value := netNode.Content[j+1]

				switch key {
				case "driver":
					net.Driver = value.Value
				case "external":
					net.External = value.Value == "true"
				}
			}
		}

		cf.Networks[name] = net
	}
}

func (cf *ComposeFile) extractVolumes(node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		name := node.Content[i].Value
		volNode := node.Content[i+1]

		vol := &Volume{Name: name, Line: volNode.Line}

		if volNode.Kind == yaml.MappingNode {
			for j := 0; j < len(volNode.Content); j += 2 {
				if j+1 >= len(volNode.Content) {
					break
				}
				key := volNode.Content[j].Value
				value := volNode.Content[j+1]

				switch key {
				case "driver":
					vol.Driver = value.Value
				case "external":
					vol.External = value.Value == "true"
				}
			}
		}

		cf.Volumes[name] = vol
	}
}

func (cf *ComposeFile) extractSecrets(node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		name := node.Content[i].Value
		secNode := node.Content[i+1]

		sec := &Secret{Name: name, Line: secNode.Line}

		if secNode.Kind == yaml.MappingNode {
			for j := 0; j < len(secNode.Content); j += 2 {
				if j+1 >= len(secNode.Content) {
					break
				}
				key := secNode.Content[j].Value
				value := secNode.Content[j+1]

				switch key {
				case "file":
					sec.File = value.Value
				case "external":
					sec.External = value.Value == "true"
				}
			}
		}

		cf.Secrets[name] = sec
	}
}

func (cf *ComposeFile) extractConfigs(node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		name := node.Content[i].Value
		cfgNode := node.Content[i+1]

		cfg := &Config{Name: name, Line: cfgNode.Line}

		if cfgNode.Kind == yaml.MappingNode {
			for j := 0; j < len(cfgNode.Content); j += 2 {
				if j+1 >= len(cfgNode.Content) {
					break
				}
				key := cfgNode.Content[j].Value
				value := cfgNode.Content[j+1]

				switch key {
				case "file":
					cfg.File = value.Value
				case "external":
					cfg.External = value.Value == "true"
				}
			}
		}

		cf.Configs[name] = cfg
	}
}

func (cf *ComposeFile) Visit(visitor ComposeVisitor) {
	for name, svc := range cf.Services {
		visitor.VisitService(name, svc)
	}
}

type ComposeVisitor interface {
	VisitService(name string, svc *Service)
}
