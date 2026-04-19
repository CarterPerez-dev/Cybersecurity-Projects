/*
©AngelaMos | 2026
index.go

Embedded MITRE ATT&CK technique catalog for honeypot detections

Maps technique IDs to their names, tactics, and descriptions for
the subset of ATT&CK techniques observable in honeypot traffic.
Covers initial access, credential access, execution, discovery,
lateral movement, and command-and-control tactics.
*/

package mitre

type Technique struct {
	ID     string
	Name   string
	Tactic string
}

type Index struct {
	techniques map[string]*Technique
}

func NewIndex() *Index {
	idx := &Index{
		techniques: make(map[string]*Technique),
	}
	idx.populate()
	return idx
}

func (i *Index) Get(id string) *Technique {
	return i.techniques[id]
}

func (i *Index) All() []*Technique {
	result := make([]*Technique, 0, len(i.techniques))
	for _, t := range i.techniques {
		result = append(result, t)
	}
	return result
}

func (i *Index) Tactics() []string {
	seen := make(map[string]bool)
	var tactics []string
	for _, t := range i.techniques {
		if !seen[t.Tactic] {
			seen[t.Tactic] = true
			tactics = append(tactics, t.Tactic)
		}
	}
	return tactics
}

func (i *Index) ByTactic(
	tactic string,
) []*Technique {
	var result []*Technique
	for _, t := range i.techniques {
		if t.Tactic == tactic {
			result = append(result, t)
		}
	}
	return result
}

func (i *Index) populate() {
	catalog := []*Technique{
		{
			ID:     "T1595",
			Name:   "Active Scanning",
			Tactic: "reconnaissance",
		},
		{
			ID:     "T1595.001",
			Name:   "Scanning IP Blocks",
			Tactic: "reconnaissance",
		},
		{
			ID:     "T1595.002",
			Name:   "Vulnerability Scanning",
			Tactic: "reconnaissance",
		},
		{
			ID:     "T1592",
			Name:   "Gather Victim Host Information",
			Tactic: "reconnaissance",
		},
		{
			ID:     "T1190",
			Name:   "Exploit Public-Facing Application",
			Tactic: "initial-access",
		},
		{
			ID:     "T1133",
			Name:   "External Remote Services",
			Tactic: "initial-access",
		},
		{
			ID:     "T1078",
			Name:   "Valid Accounts",
			Tactic: "initial-access",
		},
		{
			ID:     "T1059",
			Name:   "Command and Scripting Interpreter",
			Tactic: "execution",
		},
		{
			ID:     "T1059.004",
			Name:   "Unix Shell",
			Tactic: "execution",
		},
		{
			ID:     "T1053.003",
			Name:   "Cron",
			Tactic: "execution",
		},
		{
			ID:     "T1110",
			Name:   "Brute Force",
			Tactic: "credential-access",
		},
		{
			ID:     "T1110.001",
			Name:   "Password Guessing",
			Tactic: "credential-access",
		},
		{
			ID:     "T1110.003",
			Name:   "Password Spraying",
			Tactic: "credential-access",
		},
		{
			ID:     "T1082",
			Name:   "System Information Discovery",
			Tactic: "discovery",
		},
		{
			ID:     "T1083",
			Name:   "File and Directory Discovery",
			Tactic: "discovery",
		},
		{
			ID:     "T1046",
			Name:   "Network Service Discovery",
			Tactic: "discovery",
		},
		{
			ID:     "T1016",
			Name:   "System Network Configuration Discovery",
			Tactic: "discovery",
		},
		{
			ID:     "T1057",
			Name:   "Process Discovery",
			Tactic: "discovery",
		},
		{
			ID:     "T1021",
			Name:   "Remote Services",
			Tactic: "lateral-movement",
		},
		{
			ID:     "T1021.004",
			Name:   "SSH",
			Tactic: "lateral-movement",
		},
		{
			ID:     "T1105",
			Name:   "Ingress Tool Transfer",
			Tactic: "command-and-control",
		},
		{
			ID:     "T1071",
			Name:   "Application Layer Protocol",
			Tactic: "command-and-control",
		},
		{
			ID:     "T1071.001",
			Name:   "Web Protocols",
			Tactic: "command-and-control",
		},
		{
			ID:     "T1505.003",
			Name:   "Web Shell",
			Tactic: "persistence",
		},
		{
			ID:     "T1219",
			Name:   "Remote Access Software",
			Tactic: "command-and-control",
		},
		{
			ID:     "T1498",
			Name:   "Network Denial of Service",
			Tactic: "impact",
		},
		{
			ID:     "T1496",
			Name:   "Resource Hijacking",
			Tactic: "impact",
		},
	}

	for _, t := range catalog {
		i.techniques[t.ID] = t
	}
}
