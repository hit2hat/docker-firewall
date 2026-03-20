package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
)

const (
	syncInterval = 3 * time.Second
	ProtoTCP byte = 6
	ProtoUDP byte = 17
	PortDNS  byte = 53
)

type FWConfig struct {
	Enabled     bool
	Ports       []uint16
	InEnabled   bool
	InMode      string
	InSource    []net.IP
	InServices  []string
	OutEnabled  bool
	OutMode     string
	OutSource   []net.IP
	OutServices []string
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Failed to initialize Docker client: %v", err)
	}

	log.Printf("Firewall operator started. Reconciliation interval: %v", syncInterval)

	for {
		reconcile(ctx, cli)

		select {
		case <-time.After(syncInterval):
		case <-ctx.Done():
			log.Println("Shutting down firewall operator")
			return
		}
	}
}

func reconcile(ctx context.Context, cli *client.Client) {
	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		log.Printf("Failed to list containers: %v", err)
		return
	}

	var wg sync.WaitGroup
	for _, c := range containers {
		wg.Add(1)
		go func(containerID string) {
			defer wg.Done()
			processContainer(ctx, cli, containerID)
		}(c.ID)
	}

	wg.Wait()
}

func processContainer(ctx context.Context, cli *client.Client, containerID string) {
	inspect, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		log.Printf("[ID: %s] Failed to inspect container: %v", containerID[:10], err)
		return
	}

	cfg := parseConfig(inspect.Config.Labels)
	if !cfg.Enabled {
		return
	}

	containerName := strings.TrimPrefix(inspect.Name, "/")

	if len(cfg.Ports) == 0 {
		return
	}

	pid := inspect.State.Pid
	if pid == 0 {
		return
	}

	if err := safeApplyFirewallState(ctx, pid, cfg, containerName); err != nil {
		log.Printf("[%s] Failed to apply firewall state: %v", containerName, err)
	}
}

func safeApplyFirewallState(ctx context.Context, pid int, cfg *FWConfig, containerName string) error {
	errCh := make(chan error, 1)

	go func() {
		runtime.LockOSThread()

		hostNs, err := netns.Get()
		if err != nil {
			errCh <- fmt.Errorf("failed to get host netns: %w", err)
			return
		}
		defer hostNs.Close()

		targetNs, err := netns.GetFromPid(pid)
		if err != nil {
			errCh <- fmt.Errorf("failed to get target netns for pid %d: %w", pid, err)
			return
		}
		defer targetNs.Close()

		if err := netns.Set(targetNs); err != nil {
			errCh <- fmt.Errorf("failed to switch to target netns: %w", err)
			return
		}

		workErr := applyFirewallState(ctx, cfg, containerName)

		if restoreErr := netns.Set(hostNs); restoreErr != nil {
			log.Printf("[%s] CRITICAL: Failed to restore host netns, OS thread will be discarded: %v", containerName, restoreErr)
		} else {
			runtime.UnlockOSThread()
		}

		errCh <- workErr
	}()

	return <-errCh
}

func applyFirewallState(ctx context.Context, cfg *FWConfig, containerName string) error {
	inResolvedIPs := resolveServicesInNetns(ctx, cfg.InServices)
	outResolvedIPs := resolveServicesInNetns(ctx, cfg.OutServices)

	allInIPs := append(cfg.InSource, inResolvedIPs...)
	allOutIPs := append(cfg.OutSource, outResolvedIPs...)

	nfConn := &nftables.Conn{}
	tables, err := nfConn.ListTables()
	if err != nil {
		return fmt.Errorf("failed to list nftables tables: %w", err)
	}

	var fwTable *nftables.Table
	for _, t := range tables {
		if t.Name == "firewall" && t.Family == nftables.TableFamilyIPv4 {
			fwTable = t
			break
		}
	}

	if fwTable == nil {
		log.Printf("[%s] Initializing firewall table, chains, and sets", containerName)
		fwTable = nfConn.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "firewall"})

		portsSet := &nftables.Set{Table: fwTable, Name: "global_ports", KeyType: nftables.TypeInetService}
		inIPSet := &nftables.Set{Table: fwTable, Name: "in_ips", KeyType: nftables.TypeIPAddr}
		outIPSet := &nftables.Set{Table: fwTable, Name: "out_ips", KeyType: nftables.TypeIPAddr}

		nfConn.AddSet(portsSet, nil)
		nfConn.AddSet(inIPSet, nil)
		nfConn.AddSet(outIPSet, nil)

		buildChainsAndRules(nfConn, fwTable, cfg, portsSet, inIPSet, outIPSet)

		if err := nfConn.Flush(); err != nil {
			return fmt.Errorf("failed to apply base rules: %w", err)
		}
	}

	if err := syncSets(nfConn, fwTable, cfg, allInIPs, allOutIPs, containerName); err != nil {
		return fmt.Errorf("failed to sync sets: %w", err)
	}

	return nil
}

func buildChainsAndRules(nfConn *nftables.Conn, table *nftables.Table, cfg *FWConfig, portsSet, inSet, outSet *nftables.Set) {
	inPolicy := nftables.ChainPolicyAccept
	if cfg.InEnabled && cfg.InMode == "whitelist" {
		inPolicy = nftables.ChainPolicyDrop
	}
	inChain := nfConn.AddChain(&nftables.Chain{
		Name: "input", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &inPolicy,
	})

	addConntrackRule(nfConn, table, inChain)
	addLoopbackRule(nfConn, table, inChain, true)

	for _, proto := range []byte{ProtoTCP, ProtoUDP} {
		nfConn.AddRule(&nftables.Rule{
			Table: table, Chain: inChain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Lookup{SourceRegister: 1, SetName: portsSet.Name, SetID: portsSet.ID, Invert: true},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	if cfg.InEnabled {
		verdict := expr.VerdictDrop
		if cfg.InMode == "whitelist" {
			verdict = expr.VerdictAccept
		}
		nfConn.AddRule(&nftables.Rule{
			Table: table, Chain: inChain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Lookup{SourceRegister: 1, SetName: inSet.Name, SetID: inSet.ID},
				&expr.Verdict{Kind: verdict},
			},
		})
	}

	outPolicy := nftables.ChainPolicyAccept
	if cfg.OutEnabled && cfg.OutMode == "whitelist" {
		outPolicy = nftables.ChainPolicyDrop
	}
	outChain := nfConn.AddChain(&nftables.Chain{
		Name: "postrouting", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityFilter, Policy: &outPolicy,
	})

	addConntrackRule(nfConn, table, outChain)
	addLoopbackRule(nfConn, table, outChain, false)
	addDockerDNSRule(nfConn, table, outChain)

	if cfg.OutEnabled {
		verdict := expr.VerdictDrop
		if cfg.OutMode == "whitelist" {
			verdict = expr.VerdictAccept
		}
		nfConn.AddRule(&nftables.Rule{
			Table: table, Chain: outChain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Lookup{SourceRegister: 1, SetName: outSet.Name, SetID: outSet.ID},
				&expr.Verdict{Kind: verdict},
			},
		})
	}
}

func syncSets(nfConn *nftables.Conn, table *nftables.Table, cfg *FWConfig, inIPs, outIPs []net.IP, containerName string) error {
	var desiredPorts [][]byte
	for _, p := range cfg.Ports {
		pb := make([]byte, 2)
		binary.BigEndian.PutUint16(pb, p)
		desiredPorts = append(desiredPorts, pb)
	}

	var desiredInIPs, desiredOutIPs [][]byte
	for _, ip := range inIPs {
		if ip4 := ip.To4(); ip4 != nil {
			desiredInIPs = append(desiredInIPs, ip4)
		}
	}
	for _, ip := range outIPs {
		if ip4 := ip.To4(); ip4 != nil {
			desiredOutIPs = append(desiredOutIPs, ip4)
		}
	}

	applySetDiff := func(setName string, desired [][]byte) error {
		set, err := nfConn.GetSetByName(table, setName)
		if err != nil {
			return err
		}

		currentElements, err := nfConn.GetSetElements(set)
		if err != nil {
			return err
		}

		currentMap := make(map[string]nftables.SetElement, len(currentElements))
		for _, el := range currentElements {
			currentMap[string(el.Key)] = el
		}

		formatElement := func(b []byte) string {
			if setName == "global_ports" && len(b) >= 2 {
				return strconv.Itoa(int(binary.BigEndian.Uint16(b)))
			}
			return net.IP(b).String()
		}

		desiredMap := make(map[string]struct{}, len(desired))
		var toAdd, toDelete []nftables.SetElement
		var logDiff []string
		var finalState []string

		for _, k := range desired {
			strKey := string(k)
			desiredMap[strKey] = struct{}{}

			formattedEl := formatElement(k)
			finalState = append(finalState, formattedEl)

			if _, exists := currentMap[strKey]; !exists {
				toAdd = append(toAdd, nftables.SetElement{Key: k})
				logDiff = append(logDiff, "+"+formattedEl)
			}
		}

		for keyStr, el := range currentMap {
			if _, exists := desiredMap[keyStr]; !exists {
				toDelete = append(toDelete, el)
				logDiff = append(logDiff, "-"+formatElement(el.Key))
			}
		}

		if len(logDiff) > 0 {
			log.Printf("[%s] Updated set '%s': [%s] %s",
				containerName,
				setName,
				strings.Join(finalState, ", "),
				strings.Join(logDiff, " "))
		}

		if len(toAdd) > 0 {
			if err := nfConn.SetAddElements(set, toAdd); err != nil {
				return err
			}
		}
		if len(toDelete) > 0 {
			if err := nfConn.SetDeleteElements(set, toDelete); err != nil {
				return err
			}
		}
		return nil
	}

	if err := applySetDiff("global_ports", desiredPorts); err != nil {
		return fmt.Errorf("sync global_ports: %w", err)
	}
	if err := applySetDiff("in_ips", desiredInIPs); err != nil {
		return fmt.Errorf("sync in_ips: %w", err)
	}
	if err := applySetDiff("out_ips", desiredOutIPs); err != nil {
		return fmt.Errorf("sync out_ips: %w", err)
	}

	return nfConn.Flush()
}

func resolveServicesInNetns(ctx context.Context, services []string) []net.IP {
	var resolved []net.IP
	if len(services) == 0 {
		return resolved
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(dialCtx, "udp", "127.0.0.11:53")
		},
	}

	for _, svc := range services {
		if ips, err := resolver.LookupIP(ctx, "ip4", svc); err == nil {
			resolved = append(resolved, ips...)
		}

		if ips, err := resolver.LookupIP(ctx, "ip4", "tasks."+svc); err == nil {
			resolved = append(resolved, ips...)
		}
	}
	return resolved
}

func parseConfig(labels map[string]string) *FWConfig {
	cfg := &FWConfig{
		Enabled:    labels["firewall.enabled"] == "true",
		InEnabled:  labels["firewall.in.enabled"] == "true",
		InMode:     labels["firewall.in.mode"],
		OutEnabled: labels["firewall.out.enabled"] == "true",
		OutMode:    labels["firewall.out.mode"],
	}

	for _, pStr := range strings.Split(labels["firewall.ports"], ",") {
		p, err := strconv.ParseUint(strings.TrimSpace(pStr), 10, 16)
		if err == nil {
			cfg.Ports = append(cfg.Ports, uint16(p))
		}
	}
	cfg.InSource = parseIPList(labels["firewall.in.source"])
	cfg.InServices = parseStringList(labels["firewall.in.services"])
	cfg.OutSource = parseIPList(labels["firewall.out.source"])
	cfg.OutServices = parseStringList(labels["firewall.out.services"])

	return cfg
}

func parseIPList(str string) []net.IP {
	var ips []net.IP
	if str == "" {
		return ips
	}
	for _, s := range strings.Split(str, ",") {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip != nil && ip.To4() != nil {
			ips = append(ips, ip.To4())
		}
	}
	return ips
}

func parseStringList(str string) []string {
	var list []string
	if str == "" {
		return list
	}
	for _, s := range strings.Split(str, ",") {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			list = append(list, trimmed)
		}
	}
	return list
}

func addConntrackRule(nfConn *nftables.Conn, table *nftables.Table, chain *nftables.Chain) {
	nfConn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{0x06, 0x00, 0x00, 0x00}, Xor: []byte{0x00, 0x00, 0x00, 0x00}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
}

func addLoopbackRule(nfConn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, isInput bool) {
	loName := make([]byte, 16)
	copy(loName, "lo")
	metaKey := expr.MetaKeyIIFNAME
	if !isInput {
		metaKey = expr.MetaKeyOIFNAME
	}
	nfConn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: metaKey, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: loName},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
}

func addDockerDNSRule(nfConn *nftables.Conn, table *nftables.Table, chain *nftables.Chain) {
	dnsIP := net.ParseIP("127.0.0.11").To4()
	for _, proto := range []byte{ProtoUDP, ProtoTCP} {
		nfConn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dnsIP},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, PortDNS}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}
}
