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
	"os/exec"
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
