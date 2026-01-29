/*
AngelaMos | 2026
compose.go
*/

package analyzer

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/CarterPerez-dev/docksec/internal/finding"
	"github.com/CarterPerez-dev/docksec/internal/rules"
	"gopkg.in/yaml.v3"
)

type ComposeAnalyzer struct {
	path string
}

func NewComposeAnalyzer(path string) *ComposeAnalyzer {
	return &ComposeAnalyzer{path: path}
}

func (a *ComposeAnalyzer) Name() string {
	return "compose:" + a.path
}

func (a *ComposeAnalyzer) Analyze(
	ctx context.Context,
) (finding.Collection, error) {
	data, err := os.ReadFile(a.path)
	if err != nil {
		return nil, err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	target := finding.Target{
		Type: finding.TargetCompose,
		Name: a.path,
	}

	var findings finding.Collection

	services := findNode(&root, "services")
	if services == nil {
		return findings, nil
	}

	for i := 0; i < len(services.Content); i += 2 {
		if i+1 >= len(services.Content) {
			break
		}
		serviceName := services.Content[i].Value
		serviceNode := services.Content[i+1]

		findings = append(
			findings,
			a.analyzeService(target, serviceName, serviceNode)...)
	}

	return findings, nil
}

func (a *ComposeAnalyzer) analyzeService(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	findings = append(
		findings,
		a.checkPrivileged(target, serviceName, node)...)
	findings = append(
		findings,
		a.checkCapabilities(target, serviceName, node)...)
	findings = append(findings, a.checkVolumes(target, serviceName, node)...)
	findings = append(
		findings,
		a.checkNetworkMode(target, serviceName, node)...)
	findings = append(findings, a.checkPidMode(target, serviceName, node)...)
	findings = append(findings, a.checkIpcMode(target, serviceName, node)...)
	findings = append(
		findings,
		a.checkSecurityOpt(target, serviceName, node)...)
	findings = append(
		findings,
		a.checkResourceLimits(target, serviceName, node)...)
	findings = append(
		findings,
		a.checkEnvironment(target, serviceName, node)...)
	findings = append(findings, a.checkPorts(target, serviceName, node)...)
	findings = append(findings, a.checkUser(target, serviceName, node)...)
	findings = append(findings, a.checkReadOnly(target, serviceName, node)...)

	return findings
}

func (a *ComposeAnalyzer) checkPrivileged(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	privNode := findNode(node, "privileged")
	if privNode != nil &&
		(privNode.Value == "true" || privNode.Value == "yes") {
		loc := &finding.Location{Path: a.path, Line: privNode.Line}
		f := finding.New("CIS-5.4", "Service '"+serviceName+"' runs in privileged mode", finding.SeverityCritical, target).
			WithDescription("Privileged containers have full access to host devices and bypass security features.").
			WithCategory(string(CategoryCompose)).
			WithLocation(loc).
			WithRemediation("Remove 'privileged: true' and use specific capabilities instead.")
		findings = append(findings, f)
	}

	return findings
}

func (a *ComposeAnalyzer) checkCapabilities(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	capAddNode := findNode(node, "cap_add")
	if capAddNode == nil {
		return findings
	}

	for _, capNode := range capAddNode.Content {
		capName := strings.ToUpper(capNode.Value)
		capInfo, exists := rules.GetCapabilityInfo(capName)
		if !exists {
			continue
		}

		if capInfo.Severity >= finding.SeverityHigh {
			loc := &finding.Location{Path: a.path, Line: capNode.Line}
			title := "Service '" + serviceName + "' adds dangerous capability: " + capName
			if capInfo.Severity == finding.SeverityCritical {
				title = "Service '" + serviceName + "' adds critical capability: " + capName
			}
			f := finding.New("CIS-5.3", title, capInfo.Severity, target).
				WithDescription(capInfo.Description).
				WithCategory(string(CategoryCompose)).
				WithLocation(loc).
				WithRemediation("Remove unnecessary capabilities. Use --cap-drop=ALL and add only required capabilities.")
			findings = append(findings, f)
		}
	}

	return findings
}

func (a *ComposeAnalyzer) checkVolumes(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	volumesNode := findNode(node, "volumes")
	if volumesNode == nil {
		return findings
	}

	for _, volNode := range volumesNode.Content {
		var hostPath string
		switch volNode.Kind {
		case yaml.ScalarNode:
			parts := strings.SplitN(volNode.Value, ":", 2)
			hostPath = parts[0]
		case yaml.MappingNode:
			sourceNode := findNode(volNode, "source")
			if sourceNode != nil {
				hostPath = sourceNode.Value
			}
		}

		if hostPath == "" {
			continue
		}

		if rules.IsDockerSocket(hostPath) {
			loc := &finding.Location{Path: a.path, Line: volNode.Line}
			f := finding.New("CIS-5.31", "Service '"+serviceName+"' mounts Docker socket", finding.SeverityCritical, target).
				WithDescription("Mounting Docker socket gives the container full control over the Docker daemon.").
				WithCategory(string(CategoryCompose)).
				WithLocation(loc).
				WithRemediation("Do not mount /var/run/docker.sock inside containers.")
			findings = append(findings, f)
			continue
		}

		if rules.IsSensitivePath(hostPath) {
			loc := &finding.Location{Path: a.path, Line: volNode.Line}
			severity := rules.GetPathSeverity(hostPath)
			pathInfo, _ := rules.GetPathInfo(hostPath)
			description := "Mounting sensitive host paths can enable container escape."
			if pathInfo.Description != "" {
				description = pathInfo.Description
			}
			f := finding.New("CIS-5.5", "Service '"+serviceName+"' mounts sensitive path: "+hostPath, severity, target).
				WithDescription(description).
				WithCategory(string(CategoryCompose)).
				WithLocation(loc).
				WithRemediation("Do not mount sensitive host directories. Use Docker volumes instead.")
			findings = append(findings, f)
		}
	}

	return findings
}

func (a *ComposeAnalyzer) checkNetworkMode(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	netNode := findNode(node, "network_mode")
	if netNode != nil && netNode.Value == "host" {
		loc := &finding.Location{Path: a.path, Line: netNode.Line}
		f := finding.New("CIS-5.9", "Service '"+serviceName+"' uses host network mode", finding.SeverityHigh, target).
			WithDescription("Host network mode allows the container to access all host network interfaces.").
			WithCategory(string(CategoryCompose)).
			WithLocation(loc).
			WithRemediation("Use bridge networking instead of network_mode: host.")
		findings = append(findings, f)
	}

	return findings
}

func (a *ComposeAnalyzer) checkPidMode(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	pidNode := findNode(node, "pid")
	if pidNode != nil && pidNode.Value == "host" {
		loc := &finding.Location{Path: a.path, Line: pidNode.Line}
		f := finding.New("CIS-5.15", "Service '"+serviceName+"' shares host PID namespace", finding.SeverityHigh, target).
			WithDescription("Sharing PID namespace allows container to see and signal host processes.").
			WithCategory(string(CategoryCompose)).
			WithLocation(loc).
			WithRemediation("Remove 'pid: host' from the service definition.")
		findings = append(findings, f)
	}

	return findings
}

func (a *ComposeAnalyzer) checkIpcMode(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	ipcNode := findNode(node, "ipc")
	if ipcNode != nil && ipcNode.Value == "host" {
		loc := &finding.Location{Path: a.path, Line: ipcNode.Line}
		f := finding.New("CIS-5.16", "Service '"+serviceName+"' shares host IPC namespace", finding.SeverityHigh, target).
			WithDescription("Sharing IPC namespace allows container to access host shared memory.").
			WithCategory(string(CategoryCompose)).
			WithLocation(loc).
			WithRemediation("Remove 'ipc: host' from the service definition.")
		findings = append(findings, f)
	}

	return findings
}

func (a *ComposeAnalyzer) checkSecurityOpt(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	secOptNode := findNode(node, "security_opt")
	if secOptNode == nil {
		return findings
	}

	for _, optNode := range secOptNode.Content {
		opt := strings.ToLower(optNode.Value)

		if opt == "seccomp:unconfined" || opt == "seccomp=unconfined" {
			loc := &finding.Location{Path: a.path, Line: optNode.Line}
			f := finding.New("CIS-5.21", "Service '"+serviceName+"' disables seccomp profile", finding.SeverityHigh, target).
				WithDescription("Disabling seccomp removes syscall restrictions from the container.").
				WithCategory(string(CategoryCompose)).
				WithLocation(loc).
				WithRemediation("Remove 'seccomp:unconfined' and use default or custom seccomp profile.")
			findings = append(findings, f)
		}

		if opt == "apparmor:unconfined" || opt == "apparmor=unconfined" {
			loc := &finding.Location{Path: a.path, Line: optNode.Line}
			f := finding.New("CIS-5.1", "Service '"+serviceName+"' disables AppArmor profile", finding.SeverityHigh, target).
				WithDescription("Disabling AppArmor removes mandatory access control from the container.").
				WithCategory(string(CategoryCompose)).
				WithLocation(loc).
				WithRemediation("Remove 'apparmor:unconfined' and use default or custom AppArmor profile.")
			findings = append(findings, f)
		}
	}

	return findings
}

func (a *ComposeAnalyzer) checkResourceLimits(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	deployNode := findNode(node, "deploy")
	var resourcesNode *yaml.Node
	if deployNode != nil {
		resourcesNode = findNode(deployNode, "resources")
	}

	memLimitNode := findNode(node, "mem_limit")
	cpuLimitNode := findNode(node, "cpus")
	pidsLimitNode := findNode(node, "pids_limit")

	hasMemLimit := memLimitNode != nil
	hasCpuLimit := cpuLimitNode != nil
	hasPidsLimit := pidsLimitNode != nil

	if resourcesNode != nil {
		limitsNode := findNode(resourcesNode, "limits")
		if limitsNode != nil {
			if findNode(limitsNode, "memory") != nil {
				hasMemLimit = true
			}
			if findNode(limitsNode, "cpus") != nil {
				hasCpuLimit = true
			}
			if findNode(limitsNode, "pids") != nil {
				hasPidsLimit = true
			}
		}
	}

	if !hasMemLimit {
		loc := &finding.Location{Path: a.path, Line: node.Line}
		f := finding.New("CIS-5.10", "Service '"+serviceName+"' has no memory limit", finding.SeverityMedium, target).
			WithDescription("Without memory limits, a container can exhaust all available host memory.").
			WithCategory(string(CategoryCompose)).
			WithLocation(loc).
			WithRemediation("Set mem_limit or deploy.resources.limits.memory for the service.")
		findings = append(findings, f)
	}

	if !hasCpuLimit {
		loc := &finding.Location{Path: a.path, Line: node.Line}
		f := finding.New("CIS-5.11", "Service '"+serviceName+"' has no CPU limit", finding.SeverityMedium, target).
			WithDescription("Without CPU limits, a container can consume all available CPU resources.").
			WithCategory(string(CategoryCompose)).
			WithLocation(loc).
			WithRemediation("Set cpus or deploy.resources.limits.cpus for the service.")
		findings = append(findings, f)
	}

	if !hasPidsLimit {
		loc := &finding.Location{Path: a.path, Line: node.Line}
		f := finding.New("CIS-5.28", "Service '"+serviceName+"' has no PIDs limit", finding.SeverityMedium, target).
			WithDescription("Without PIDs limits, a container can fork-bomb and exhaust process table.").
			WithCategory(string(CategoryCompose)).
			WithLocation(loc).
			WithRemediation("Set pids_limit or deploy.resources.limits.pids for the service.")
		findings = append(findings, f)
	}

	return findings
}

func (a *ComposeAnalyzer) checkEnvironment(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	envNode := findNode(node, "environment")
	if envNode == nil {
		return findings
	}

	if envNode.Kind == yaml.MappingNode {
		for i := 0; i < len(envNode.Content); i += 2 {
			if i+1 >= len(envNode.Content) {
				break
			}
			keyNode := envNode.Content[i]
			valueNode := envNode.Content[i+1]

			if rules.IsSensitiveEnvName(keyNode.Value) &&
				valueNode.Value != "" {
				if !isVariableReference(valueNode.Value) {
					loc := &finding.Location{Path: a.path, Line: keyNode.Line}
					f := finding.New("CIS-4.10", "Service '"+serviceName+"' has sensitive variable '"+keyNode.Value+"' with hardcoded value", finding.SeverityHigh, target).
						WithDescription("Hardcoding secrets in compose files exposes them in version control.").
						WithCategory(string(CategoryCompose)).
						WithLocation(loc).
						WithRemediation("Use environment variable substitution: ${" + keyNode.Value + "} or Docker secrets.")
					findings = append(findings, f)
				}
			}

			secrets := rules.DetectSecrets(valueNode.Value)
			for _, secret := range secrets {
				loc := &finding.Location{Path: a.path, Line: valueNode.Line}
				f := finding.New("CIS-4.10", "Service '"+serviceName+"' may contain "+string(secret.Type)+" in environment", finding.SeverityHigh, target).
					WithDescription(secret.Description + " detected in environment variable.").
					WithCategory(string(CategoryCompose)).
					WithLocation(loc).
					WithRemediation("Remove secrets from compose file. Use Docker secrets or external secret management.")
				findings = append(findings, f)
			}
		}
	} else if envNode.Kind == yaml.SequenceNode {
		for _, itemNode := range envNode.Content {
			parts := strings.SplitN(itemNode.Value, "=", 2)
			if len(parts) < 2 {
				continue
			}
			varName := parts[0]
			varValue := parts[1]

			if rules.IsSensitiveEnvName(varName) && varValue != "" {
				if !isVariableReference(varValue) {
					loc := &finding.Location{Path: a.path, Line: itemNode.Line}
					f := finding.New("CIS-4.10", "Service '"+serviceName+"' has sensitive variable '"+varName+"' with hardcoded value", finding.SeverityHigh, target).
						WithDescription("Hardcoding secrets in compose files exposes them in version control.").
						WithCategory(string(CategoryCompose)).
						WithLocation(loc).
						WithRemediation("Use environment variable substitution: ${" + varName + "} or Docker secrets.")
					findings = append(findings, f)
				}
			}

			secrets := rules.DetectSecrets(varValue)
			for _, secret := range secrets {
				loc := &finding.Location{Path: a.path, Line: itemNode.Line}
				f := finding.New("CIS-4.10", "Service '"+serviceName+"' may contain "+string(secret.Type)+" in environment", finding.SeverityHigh, target).
					WithDescription(secret.Description + " detected in environment variable.").
					WithCategory(string(CategoryCompose)).
					WithLocation(loc).
					WithRemediation("Remove secrets from compose file. Use Docker secrets or external secret management.")
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func (a *ComposeAnalyzer) checkPorts(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	portsNode := findNode(node, "ports")
	if portsNode == nil {
		return findings
	}

	for _, portNode := range portsNode.Content {
		var portSpec string
		switch portNode.Kind {
		case yaml.ScalarNode:
			portSpec = portNode.Value
		case yaml.MappingNode:
			publishedNode := findNode(portNode, "published")
			hostIPNode := findNode(portNode, "host_ip")
			if publishedNode != nil {
				portSpec = publishedNode.Value
			}
			if hostIPNode != nil && hostIPNode.Value == "0.0.0.0" {
				loc := &finding.Location{Path: a.path, Line: hostIPNode.Line}
				f := finding.New("DS-COMPOSE-BIND", "Service '"+serviceName+"' explicitly binds to 0.0.0.0", finding.SeverityInfo, target).
					WithDescription("Binding to 0.0.0.0 exposes the port on all network interfaces.").
					WithCategory(string(CategoryCompose)).
					WithLocation(loc).
					WithRemediation("Consider binding to 127.0.0.1 for local-only access.")
				findings = append(findings, f)
			}
		}

		if portSpec == "" {
			continue
		}

		parts := strings.Split(portSpec, ":")
		var hostPort string
		if len(parts) >= 2 {
			hostPort = parts[0]
			if strings.Contains(hostPort, ".") {
				hostPort = parts[1]
			}
		}

		if hostPort != "" {
			portNum, err := strconv.Atoi(hostPort)
			if err == nil && portNum > 0 && portNum < 1024 {
				loc := &finding.Location{Path: a.path, Line: portNode.Line}
				f := finding.New("DS-COMPOSE-PRIVPORT", "Service '"+serviceName+"' exposes privileged port "+hostPort, finding.SeverityInfo, target).
					WithDescription("Privileged ports (below 1024) typically require root privileges on the host.").
					WithCategory(string(CategoryCompose)).
					WithLocation(loc).
					WithRemediation("Consider using non-privileged ports (>1024) with port mapping.")
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func (a *ComposeAnalyzer) checkUser(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	userNode := findNode(node, "user")
	if userNode == nil {
		loc := &finding.Location{Path: a.path, Line: node.Line}
		f := finding.New("CIS-4.1", "Service '"+serviceName+"' does not specify user", finding.SeverityMedium, target).
			WithDescription("Without a user specification, the container may run as root.").
			WithCategory(string(CategoryCompose)).
			WithLocation(loc).
			WithRemediation("Add 'user: \"1000:1000\"' or use the USER directive in the Dockerfile.")
		findings = append(findings, f)
	} else if userNode.Value == "root" || userNode.Value == "0" || userNode.Value == "0:0" {
		loc := &finding.Location{Path: a.path, Line: userNode.Line}
		f := finding.New("DS-COMPOSE-ROOT", "Service '"+serviceName+"' explicitly runs as root", finding.SeverityMedium, target).
			WithDescription("Running containers as root increases the risk of container escape.").
			WithCategory(string(CategoryCompose)).
			WithLocation(loc).
			WithRemediation("Create and use a non-root user in the Dockerfile or compose file.")
		findings = append(findings, f)
	}

	return findings
}

func (a *ComposeAnalyzer) checkReadOnly(
	target finding.Target,
	serviceName string,
	node *yaml.Node,
) finding.Collection {
	var findings finding.Collection

	readOnlyNode := findNode(node, "read_only")
	if readOnlyNode == nil || readOnlyNode.Value != "true" {
		loc := &finding.Location{Path: a.path, Line: node.Line}
		f := finding.New("CIS-5.12", "Service '"+serviceName+"' does not use read-only root filesystem", finding.SeverityMedium, target).
			WithDescription("A writable root filesystem allows attackers to modify container binaries.").
			WithCategory(string(CategoryCompose)).
			WithLocation(loc).
			WithRemediation("Add 'read_only: true' and use tmpfs volumes for writable directories.")
		findings = append(findings, f)
	}

	return findings
}

func findNode(node *yaml.Node, key string) *yaml.Node {
	if node == nil {
		return nil
	}

	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return findNode(node.Content[0], key)
	}

	if node.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}

	return nil
}

func isVariableReference(value string) bool {
	return strings.HasPrefix(value, "${") || strings.HasPrefix(value, "$")
}
