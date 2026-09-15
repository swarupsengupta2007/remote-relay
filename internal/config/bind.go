package config

import (
	"fmt"
	"net"
	"strings"
)

var InterfaceByName = net.InterfaceByName

type parsedBinding struct {
	val   string
	proto string // "tcp", "udp", or ""
}

func parseBindingEntry(entry string) ([]parsedBinding, error) {
	rawItems := strings.Split(entry, ",")
	var items []parsedBinding
	for _, raw := range rawItems {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if strings.Count(item, "@") > 1 {
			return nil, fmt.Errorf("invalid binding syntax %q: multiple '@' separators", item)
		}
		idx := strings.Index(item, "@")
		if idx == -1 {
			items = append(items, parsedBinding{val: item, proto: ""})
			continue
		}
		val := strings.TrimSpace(item[:idx])
		proto := strings.ToLower(strings.TrimSpace(item[idx+1:]))
		if val == "" {
			return nil, fmt.Errorf("invalid binding syntax %q: missing value before '@'", item)
		}
		if proto == "" {
			return nil, fmt.Errorf("invalid binding syntax %q: missing protocol after '@'", item)
		}
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("invalid binding syntax %q: unknown protocol %q (expected tcp or udp)", item, proto)
		}
		items = append(items, parsedBinding{val: val, proto: proto})
	}
	return items, nil
}

func resolveBindingsInScope(entries []string, fieldName string) (tcpVal, udpVal string, tcpSet, udpSet bool, err error) {
	for _, entry := range entries {
		parsed, err := parseBindingEntry(entry)
		if err != nil {
			return "", "", false, false, err
		}
		for _, item := range parsed {
			switch item.proto {
			case "tcp":
				if tcpSet {
					return "", "", false, false, fmt.Errorf("conflicting/duplicate %s for tcp: already set to %q, cannot set to %q", fieldName, tcpVal, item.val)
				}
				tcpVal = item.val
				tcpSet = true
			case "udp":
				if udpSet {
					return "", "", false, false, fmt.Errorf("conflicting/duplicate %s for udp: already set to %q, cannot set to %q", fieldName, udpVal, item.val)
				}
				udpVal = item.val
				udpSet = true
			case "":
				if tcpSet || udpSet {
					return "", "", false, false, fmt.Errorf("conflicting/duplicate %s: unqualified %q conflicts with already configured protocol leg", fieldName, item.val)
				}
				tcpVal = item.val
				udpVal = item.val
				tcpSet = true
				udpSet = true
			}
		}
	}
	return tcpVal, udpVal, tcpSet, udpSet, nil
}

// ResolveClientBindings merges and validates TOML and CLI interface and source-ip bindings.
func ResolveClientBindings(tomlInterfaces, tomlSourceIPs, cliInterfaces, cliSourceIPs []string) (tcpIface, udpIface, tcpIP, udpIP string, err error) {
	// Parse interfaces
	tomlTcpIface, tomlUdpIface, tomlTcpIfaceSet, tomlUdpIfaceSet, err := resolveBindingsInScope(tomlInterfaces, "interface")
	if err != nil {
		return "", "", "", "", err
	}
	cliTcpIface, cliUdpIface, cliTcpIfaceSet, cliUdpIfaceSet, err := resolveBindingsInScope(cliInterfaces, "interface")
	if err != nil {
		return "", "", "", "", err
	}

	if cliTcpIfaceSet {
		tcpIface = cliTcpIface
	} else if tomlTcpIfaceSet {
		tcpIface = tomlTcpIface
	}

	if cliUdpIfaceSet {
		udpIface = cliUdpIface
	} else if tomlUdpIfaceSet {
		udpIface = tomlUdpIface
	}

	// Validate interfaces
	if tcpIface != "" {
		if _, err := InterfaceByName(tcpIface); err != nil {
			return "", "", "", "", fmt.Errorf("interface %q not found: %w", tcpIface, err)
		}
	}
	if udpIface != "" {
		if _, err := InterfaceByName(udpIface); err != nil {
			return "", "", "", "", fmt.Errorf("interface %q not found: %w", udpIface, err)
		}
	}

	// Parse source IPs
	tomlTcpIP, tomlUdpIP, tomlTcpIPSet, tomlUdpIPSet, err := resolveBindingsInScope(tomlSourceIPs, "source-ip")
	if err != nil {
		return "", "", "", "", err
	}
	cliTcpIP, cliUdpIP, cliTcpIPSet, cliUdpIPSet, err := resolveBindingsInScope(cliSourceIPs, "source-ip")
	if err != nil {
		return "", "", "", "", err
	}

	if cliTcpIPSet {
		tcpIP = cliTcpIP
	} else if tomlTcpIPSet {
		tcpIP = tomlTcpIP
	}

	if cliUdpIPSet {
		udpIP = cliUdpIP
	} else if tomlUdpIPSet {
		udpIP = tomlUdpIP
	}

	// Validate source IPs
	if tcpIP != "" {
		if ip := net.ParseIP(tcpIP); ip == nil {
			return "", "", "", "", fmt.Errorf("invalid source ip %q", tcpIP)
		}
	}
	if udpIP != "" {
		if ip := net.ParseIP(udpIP); ip == nil {
			return "", "", "", "", fmt.Errorf("invalid source ip %q", udpIP)
		}
	}

	return tcpIface, udpIface, tcpIP, udpIP, nil
}
