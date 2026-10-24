// ©AngelaMos | 2026
// endpoint.go

package dockerx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	EnvDockerHost    = "DOCKER_HOST"
	EnvDockerContext = "DOCKER_CONTEXT"
	EnvDockerConfig  = "DOCKER_CONFIG"
	EnvXDGRuntime    = "XDG_RUNTIME_DIR"

	SourceEnvHost       = "DOCKER_HOST"
	SourceEnvContext    = "DOCKER_CONTEXT"
	SourceConfigContext = "docker context"
	SourceRootless      = "rootless socket"
	SourceDefault       = "default socket"
	SourceNone          = "none"

	unixScheme     = "unix://"
	defaultContext = "default"
	dockerDir      = ".docker"
	configFile     = "config.json"
	contextsDir    = "contexts"
	contextMetaDir = "meta"
	contextMeta    = "meta.json"
	dockerEndpoint = "docker"

	errUnresolvableContext = "%w: %s names the context %q, but its metadata could not be read"
)

var ErrContextUnresolvable = errors.New(
	"the selected Docker context could not be resolved",
)

type Endpoint struct {
	Host   string
	Source string
	Name   string
}

type dockerConfig struct {
	CurrentContext string `json:"currentContext"`
}

type contextMetadata struct {
	Name      string `json:"Name"`
	Endpoints map[string]struct {
		Host string `json:"Host"`
	} `json:"Endpoints"`
}

func ResolveEndpoint(
	environ func(string) string,
	home string,
) (Endpoint, error) {
	config := environ(EnvDockerConfig)
	if config == "" {
		config = filepath.Join(home, dockerDir)
	}
	if host := environ(EnvDockerHost); host != "" {
		return Endpoint{Host: host, Source: SourceEnvHost}, nil
	}

	// An explicit DOCKER_CONTEXT=default SELECTS the default endpoint rather
	// than meaning "unset". Treating it as unset diverges from the CLI, so
	// khaos would inject on one machine while `docker compose` acted on
	// another. DOCKER_HOST outranks DOCKER_CONTEXT, hence the order here.
	if name := environ(EnvDockerContext); name == defaultContext {
		return defaultEndpoint(environ)
	}

	if name := environ(EnvDockerContext); name != "" {
		host, ok := contextHost(config, name)
		if !ok {
			return Endpoint{}, fmt.Errorf(
				errUnresolvableContext,
				ErrContextUnresolvable,
				EnvDockerContext,
				name,
			)
		}
		return Endpoint{Host: host, Source: SourceEnvContext, Name: name}, nil
	}

	if name, ok := currentContext(config); ok && name != defaultContext {
		host, found := contextHost(config, name)
		if !found {
			return Endpoint{}, fmt.Errorf(
				errUnresolvableContext,
				ErrContextUnresolvable,
				SourceConfigContext,
				name,
			)
		}
		return Endpoint{
			Host:   host,
			Source: SourceConfigContext,
			Name:   name,
		}, nil
	}

	return defaultEndpoint(environ)
}

// defaultEndpoint is the `default` context: the rootless socket when one is
// present, otherwise the system socket.
func defaultEndpoint(environ func(string) string) (Endpoint, error) {
	if runtimeDir := environ(EnvXDGRuntime); runtimeDir != "" {
		path := filepath.Join(runtimeDir, socketBaseName)
		if exists(path) {
			return Endpoint{
				Host:   unixScheme + path,
				Source: SourceRootless,
			}, nil
		}
	}

	if exists(DockerSocketPath) {
		return Endpoint{
			Host:   unixScheme + DockerSocketPath,
			Source: SourceDefault,
		}, nil
	}

	return Endpoint{Source: SourceNone}, ErrNoEndpoint
}

func xdgRuntimeDir() string {
	return os.Getenv(EnvXDGRuntime)
}

func (e Endpoint) SocketPath() (string, bool) {
	if !strings.HasPrefix(e.Host, unixScheme) {
		return "", false
	}
	return strings.TrimPrefix(e.Host, unixScheme), true
}

func currentContext(config string) (string, bool) {
	//nolint:gosec // the operator's own ~/.docker/config.json
	raw, err := os.ReadFile(filepath.Join(config, configFile))
	if err != nil {
		return "", false
	}

	var cfg dockerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", false
	}

	return cfg.CurrentContext, cfg.CurrentContext != ""
}

func contextHost(config, name string) (string, bool) {
	digest := sha256.Sum256([]byte(name))
	path := filepath.Join(
		config,
		contextsDir,
		contextMetaDir,
		hex.EncodeToString(digest[:]),
		contextMeta,
	)

	//nolint:gosec // a path khaos derives under the operator's ~/.docker
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}

	var meta contextMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		return "", false
	}

	endpoint, ok := meta.Endpoints[dockerEndpoint]
	if !ok || endpoint.Host == "" {
		return "", false
	}

	return endpoint.Host, true
}

func ComposeEnvironment(environ []string) ([]string, error) {
	values := make(map[string]string, len(environ))
	for _, entry := range environ {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	endpoint, err := ResolveEndpoint(func(key string) string {
		return values[key]
	}, homeDir())
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(environ)+1)
	for _, entry := range environ {
		key, _, _ := strings.Cut(entry, "=")
		if key != EnvDockerContext && key != EnvDockerHost {
			out = append(out, entry)
		}
	}
	return append(out, EnvDockerHost+"="+endpoint.Host), nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
