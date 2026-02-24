package daemon

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Version          int           `yaml:"version"`
	InternalPrefixes []string      `yaml:"internal_prefixes"`
	ExemptPorts      []int         `yaml:"exempt_ports,omitempty"`
	Applications     []Application `yaml:"applications"`
}

type Application struct {
	AppID string        `yaml:"app_id"`
	Match MatchCriteria `yaml:"match"`
	Allow []AllowEntry  `yaml:"allow"`
}

type MatchCriteria struct {
	Cgroup   string `yaml:"cgroup"`
	ExecHash string `yaml:"exec_hash,omitempty"`
}

type AllowEntry struct {
	Prefixes []string    `yaml:"prefixes"`
	Ports    []PortValue `yaml:"ports,omitempty"`
	Protocol string      `yaml:"protocol,omitempty"`
}

type PortValue struct {
	Single int    // non-zero if single port
	Range  string // non-empty if range like "8000-8099"
}

func (p *PortValue) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		// Try as integer first
		if n, err := strconv.Atoi(value.Value); err == nil {
			p.Single = n
			return nil
		}
		// Must be a range string
		if strings.Contains(value.Value, "-") {
			p.Range = value.Value
			return nil
		}
		return fmt.Errorf("invalid port value: %s", value.Value)
	default:
		return fmt.Errorf("unexpected YAML node type for port: %v", value.Kind)
	}
}

func (p *PortValue) PortRange() (uint16, uint16, error) {
	if p.Single > 0 {
		return uint16(p.Single), uint16(p.Single), nil
	}
	parts := strings.SplitN(p.Range, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port range: %s", p.Range)
	}
	lo, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range low: %w", err)
	}
	hi, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range high: %w", err)
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("port range out of bounds: %d-%d", lo, hi)
	}
	return uint16(lo), uint16(hi), nil
}

func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy: %w", err)
	}

	var pol Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}

	if err := pol.Validate(); err != nil {
		return nil, fmt.Errorf("validating policy: %w", err)
	}

	return &pol, nil
}

func (p *Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version: %d", p.Version)
	}

	if len(p.InternalPrefixes) == 0 {
		return fmt.Errorf("internal_prefixes must not be empty")
	}

	for _, cidr := range p.InternalPrefixes {
		if _, err := ParseCIDR(cidr); err != nil {
			return fmt.Errorf("internal prefix: %w", err)
		}
	}

	if len(p.Applications) == 0 {
		return fmt.Errorf("applications must not be empty")
	}

	seen := make(map[string]bool)
	for _, app := range p.Applications {
		if app.AppID == "" {
			return fmt.Errorf("app_id must not be empty")
		}
		if seen[app.AppID] {
			return fmt.Errorf("duplicate app_id: %s", app.AppID)
		}
		seen[app.AppID] = true

		if app.Match.Cgroup == "" {
			return fmt.Errorf("app %s: cgroup match must not be empty", app.AppID)
		}

		if app.Match.ExecHash != "" {
			if _, err := ParseExecHash(app.Match.ExecHash); err != nil {
				return fmt.Errorf("app %s: %w", app.AppID, err)
			}
		}

		if len(app.Allow) == 0 {
			return fmt.Errorf("app %s: allow rules must not be empty", app.AppID)
		}

		for _, rule := range app.Allow {
			if len(rule.Prefixes) == 0 {
				return fmt.Errorf("app %s: allow rule prefixes must not be empty", app.AppID)
			}
			for _, cidr := range rule.Prefixes {
				if _, err := ParseCIDR(cidr); err != nil {
					return fmt.Errorf("app %s: allow prefix: %w", app.AppID, err)
				}
			}
			for _, port := range rule.Ports {
				if _, _, err := port.PortRange(); err != nil {
					return fmt.Errorf("app %s: %w", app.AppID, err)
				}
			}
		}
	}

	return nil
}

// ParsedInternalPrefixes splits the configured prefixes into v4 and v6.
func (p *Policy) ParsedInternalPrefixes() (v4 []netip.Prefix, v6 []netip.Prefix, err error) {
	for _, cidr := range p.InternalPrefixes {
		prefix, err := ParseCIDR(cidr)
		if err != nil {
			return nil, nil, err
		}
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix)
		} else {
			v6 = append(v6, prefix)
		}
	}
	return v4, v6, nil
}
