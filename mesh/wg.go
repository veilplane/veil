// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

// The WireGuard interface. In the kernel when it can (Linux 5.6 and newer), otherwise
// wireguard-go inside this process (containers, older kernels). Both are configured the same
// way, through wgctrl: the kernel's over netlink, wireguard-go's over its UAPI socket in
// /var/run/wireguard, so "wg show" works for both.

package mesh

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wgInterface struct {
	name   string
	mode   string // kernel or userspace
	client *wgctrl.Client
	user   *device.Device // userspace only
	uapi   net.Listener
}

func ip(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// openInterface creates (or takes over) the interface and gives it the mesh address.
// mode: auto, kernel or userspace.
func openInterface(name, mode string, mtu int, address netip.Prefix) (*wgInterface, error) {
	w := &wgInterface{name: name}
	if mode == "auto" || mode == "kernel" {
		err := ip("link", "add", name, "type", "wireguard")
		if err == nil || strings.Contains(err.Error(), "File exists") {
			w.mode = "kernel"
		} else if mode == "kernel" {
			return nil, fmt.Errorf("no WireGuard in the kernel: %v", err)
		} else {
			log.Printf("no WireGuard in the kernel, using wireguard-go (%v)", err)
		}
	}
	if w.mode == "" {
		if err := w.startUserspace(mtu); err != nil {
			return nil, err
		}
		w.mode = "userspace"
	}
	if err := ip("link", "set", name, "mtu", fmt.Sprint(mtu)); err != nil {
		w.Close()
		return nil, err
	}
	if err := ip("address", "replace", address.String(), "dev", name); err != nil {
		w.Close()
		return nil, err
	}
	if err := ip("link", "set", name, "up"); err != nil {
		w.Close()
		return nil, err
	}
	c, err := wgctrl.New()
	if err != nil {
		w.Close()
		return nil, err
	}
	w.client = c
	return w, nil
}

func (w *wgInterface) startUserspace(mtu int) error {
	t, err := tun.CreateTUN(w.name, mtu)
	if err != nil {
		return fmt.Errorf("cannot create %s (wireguard-go needs /dev/net/tun): %v", w.name, err)
	}
	f, err := ipc.UAPIOpen(w.name)
	if err != nil {
		t.Close()
		return fmt.Errorf("WireGuard control socket: %v", err)
	}
	w.user = device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard-go: "))
	if w.uapi, err = ipc.UAPIListen(w.name, f); err != nil {
		w.user.Close()
		return fmt.Errorf("WireGuard control socket: %v", err)
	}
	go func() {
		for {
			c, err := w.uapi.Accept()
			if err != nil {
				return
			}
			go w.user.IpcHandle(c)
		}
	}()
	return nil
}

// Close removes the interface (kernel) or stops wireguard-go.
func (w *wgInterface) Close() {
	if w.client != nil {
		w.client.Close()
	}
	if w.uapi != nil {
		w.uapi.Close()
	}
	if w.user != nil {
		w.user.Close()
	}
	if w.mode == "kernel" {
		ip("link", "del", w.name)
	}
}

func (w *wgInterface) configure(c wgtypes.Config) error {
	if w.client == nil {
		return nil // tests
	}
	return w.client.ConfigureDevice(w.name, c)
}

func (w *wgInterface) device() (*wgtypes.Device, error) {
	return w.client.Device(w.name)
}

func udpAddr(a netip.AddrPort) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(a)
}

func hostRoute(a netip.Addr) net.IPNet {
	return net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(a.BitLen(), a.BitLen())}
}

func keepalive(d time.Duration) *time.Duration { return &d }

// ---------------------------------------------------------------- conflicts with the machine

// tailnet is the range Tailscale takes its addresses from. On Linux it drops every packet from
// this range that does not arrive through its own interface (a rule in its ts-input chain).
var tailnet = netip.MustParsePrefix("100.64.0.0/10")

// hostNet is one address or route of the machine, on an interface.
type hostNet struct {
	iface  string
	prefix netip.Prefix
	route  bool // a route, not an address of the interface
}

// conflicts tells what on this machine gets in the way of the mesh network: another interface
// with an address in it or a route into it (traffic for some mesh addresses would go there), and
// Tailscale, which would drop the other nodes' mesh packets.
func conflicts(mesh netip.Prefix, own string, nets []hostNet) []string {
	var out []string
	seen := map[string]bool{}
	tailscale := false
	for _, n := range nets {
		if strings.HasPrefix(n.iface, "tailscale") {
			tailscale = true
		}
		if n.iface == own || !n.prefix.IsValid() || n.prefix.Bits() == 0 || !n.prefix.Addr().Is4() || !n.prefix.Overlaps(mesh) {
			continue
		}
		if strings.HasPrefix(n.iface, "tailscale") && mesh.Overlaps(tailnet) {
			continue // said below, with what to do
		}
		what := "an address"
		if n.route {
			what = "a route"
		}
		msg := fmt.Sprintf("the mesh network %s overlaps %s on %s (%s): traffic for some mesh addresses may go there instead",
			mesh, n.prefix.Masked(), n.iface, what)
		if !seen[msg] {
			seen[msg] = true
			out = append(out, msg)
		}
	}
	if tailscale && mesh.Overlaps(tailnet) {
		out = append(out, fmt.Sprintf("Tailscale runs here and drops packets from %s that do not come through it, and the mesh network "+
			"%s lies in that range: the other nodes' mesh packets are dropped. The backend should hand out a mesh network outside "+
			"%s; until then: iptables -I INPUT 1 -i %s -j ACCEPT", tailnet, mesh, tailnet, own))
	}
	return out
}

// hostNets reads the machine's interface addresses and its IPv4 routes (main table).
func hostNets() []hostNet {
	var out []hostNet
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				out = append(out, hostNet{iface: i.Name, prefix: p})
			}
		}
		if len(addrs) == 0 && strings.HasPrefix(i.Name, "tailscale") {
			out = append(out, hostNet{iface: i.Name})
		}
	}
	if raw, err := os.ReadFile("/proc/net/route"); err == nil {
		out = append(out, parseRoutes(string(raw))...)
	}
	return out
}

// parseRoutes reads /proc/net/route: Iface, Destination, Gateway, Flags, ..., Mask (hex, the
// machine's byte order, which is little endian on every platform veil runs on).
func parseRoutes(table string) []hostNet {
	var out []hostNet
	for _, line := range strings.Split(table, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 8 {
			continue
		}
		dst, err1 := strconv.ParseUint(f[1], 16, 32)
		mask, err2 := strconv.ParseUint(f[7], 16, 32)
		if err1 != nil || err2 != nil || mask == 0 {
			continue // the default route overlaps everything: not a conflict
		}
		le := func(v uint64) [4]byte { return [4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
		m := le(mask)
		bits := 0
		for _, b := range m {
			for ; b&0x80 != 0; b <<= 1 {
				bits++
			}
		}
		out = append(out, hostNet{iface: f[0], prefix: netip.PrefixFrom(netip.AddrFrom4(le(dst)), bits), route: true})
	}
	return out
}
