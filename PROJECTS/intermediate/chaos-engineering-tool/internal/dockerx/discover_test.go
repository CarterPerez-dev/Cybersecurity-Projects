// ©AngelaMos | 2026
// discover_test.go

package dockerx

import (
	"errors"
	"testing"

	"github.com/moby/moby/api/types/container"
)

func inspectResponse() container.InspectResponse {
	return container.InspectResponse{
		ID:    acceptableID,
		Name:  "/shop-api-1",
		State: &container.State{Running: true},
		HostConfig: &container.HostConfig{
			NetworkMode: "shop_default",
		},
		Config: &container.Config{
			Image: "shop/api:latest",
			Labels: map[string]string{
				LabelConsent:        ConsentValue,
				LabelComposeProject: project,
			},
		},
		Mounts: []container.MountPoint{{Source: "/srv/shop/config"}},
	}
}

func TestTargetFromProducesAnAcceptableTarget(t *testing.T) {
	target, err := targetFrom(inspectResponse())
	if err != nil {
		t.Fatalf("targetFrom: %v", err)
	}

	if refusal := Refuse(target, Guard{Project: project}); refusal != nil {
		t.Fatalf(
			"a healthy inspect response produced a target refused by %s (%s)",
			refusal.Predicate,
			refusal.Reason,
		)
	}
}

func TestTargetFromRefusesAnInspectResponseWithNoHostConfig(t *testing.T) {
	raw := inspectResponse()
	raw.HostConfig = nil

	if _, err := targetFrom(raw); !errors.Is(err, ErrNoHostConfig) {
		t.Fatalf(
			"targetFrom returned %v for a nil HostConfig; it must refuse rather than zero-fill, "+
				"because zero-filled host config silently disarms every container-property predicate",
			err,
		)
	}
}

func TestTargetFromCarriesEveryFieldThePredicatesRead(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*container.InspectResponse)
		predicate string
	}{
		{"host network", func(r *container.InspectResponse) {
			r.HostConfig.NetworkMode = NetworkModeHost
		}, PredicateHostNetwork},
		{"shared namespace", func(r *container.InspectResponse) {
			r.HostConfig.NetworkMode = container.NetworkMode(
				NetworkModeContainerPfx + peerID,
			)
		}, PredicateSharedNamespace},
		{"host pid namespace", func(r *container.InspectResponse) {
			r.HostConfig.PidMode = ModeHost
		}, PredicateHostNamespace},
		{"host ipc namespace", func(r *container.InspectResponse) {
			r.HostConfig.IpcMode = ModeHost
		}, PredicateHostNamespace},
		{"host user namespace", func(r *container.InspectResponse) {
			r.HostConfig.UsernsMode = ModeHost
		}, PredicateHostNamespace},
		{"privileged", func(r *container.InspectResponse) {
			r.HostConfig.Privileged = true
		}, PredicatePrivileged},
		{"dangerous capability", func(r *container.InspectResponse) {
			r.HostConfig.CapAdd = []string{"CAP_SYS_MODULE"}
		}, PredicateDangerousCap},
		{"device passthrough", func(r *container.InspectResponse) {
			r.HostConfig.Devices = []container.DeviceMapping{
				{PathOnHost: "/dev/sda"},
			}
		}, PredicateDeviceAccess},
		{"unconfined profile", func(r *container.InspectResponse) {
			r.HostConfig.SecurityOpt = []string{"apparmor=unconfined"}
		}, PredicateUnconfined},
		{"socket mount", func(r *container.InspectResponse) {
			r.Mounts = append(
				r.Mounts,
				container.MountPoint{Source: DockerSocketPath},
			)
		}, PredicateSocketReachable},
		{"socket parent directory", func(r *container.InspectResponse) {
			r.Mounts = append(
				r.Mounts,
				container.MountPoint{Source: "/var/run"},
			)
		}, PredicateSocketReachable},
		{"not running", func(r *container.InspectResponse) {
			r.State.Running = false
		}, PredicateNotRunning},
		{"consent removed", func(r *container.InspectResponse) {
			delete(r.Config.Labels, LabelConsent)
		}, PredicateConsentMissing},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := inspectResponse()
			tc.mutate(&raw)

			target, err := targetFrom(raw)
			if err != nil {
				t.Fatalf("targetFrom: %v", err)
			}

			refusal := Refuse(target, Guard{Project: project})
			if refusal == nil {
				t.Fatalf(
					"a container that is %s was built into an accepted target; "+
						"the field the %s predicate reads is not being carried across from the daemon response",
					tc.name,
					tc.predicate,
				)
			}

			if refusal.Predicate != tc.predicate {
				t.Fatalf("a container that is %s was refused by %s, want %s",
					tc.name, refusal.Predicate, tc.predicate)
			}
		})
	}
}

func TestTargetFromSurvivesAbsentOptionalSections(t *testing.T) {
	raw := inspectResponse()
	raw.Config = nil
	raw.State = nil
	raw.Mounts = nil

	target, err := targetFrom(raw)
	if err != nil {
		t.Fatalf("targetFrom: %v", err)
	}

	refusal := Refuse(target, Guard{})
	if refusal == nil {
		t.Fatal(
			"an inspect response with no Config and no State produced an accepted target",
		)
	}
}

func TestTargetFromMarksTheTargetInspected(t *testing.T) {
	target, err := targetFrom(inspectResponse())
	if err != nil {
		t.Fatalf("targetFrom: %v", err)
	}

	if !target.Inspected {
		t.Fatal(
			"targetFrom did not mark the target as inspected, so it will be refused as incomplete",
		)
	}
}
