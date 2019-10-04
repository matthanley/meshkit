package main

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/lorenzosaino/go-sysctl"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireGuard struct {
	Client		wgctrl.Client
}

const (
	DummyLinkType			= "dummy"
	WireGuardLinkType		= "wireguard"
)

func NewWireGuard() *WireGuard {
	client, err := wgctrl.New()
	panicOnErr(err)

	return &WireGuard{
		Client: *client,
	}
}

func RealIFName(n string) string {
	return fmt.Sprintf("%s.0", n)
}

func (wg WireGuard) CreateDevice(n string, addr *net.IPNet, c wgtypes.Config) error {
	/*
		WireGuard doesn't send RTM_GETNEIGH netlink events
		since it can't use ARP for neighbour discovery.
		AFAIK there's no way to get missing neighbour
		events out of WG, so we need a workaround.

		We add a dummy interface with the specified subnet
		assigned, and add the single /32 IP to the wg iface.
		Enabling ARP on the dummy interfaces generates the
		RTM_GETNEIGH events we're looking for, and we just
		need to tell the routing table to route discovered
		peers to the wg iface.
	 */

	// >>> ip link add dummy0 type dummy
	link, err := CreateDevice(n, DummyLinkType)
	if err != nil {
		return err
	}

	// Enable broadcasting of RTM_GETNEIGH messages
	warnOnErr(sysctl.Set(fmt.Sprintf("net.ipv4.neigh.%s.app_solicit", link.Attrs().Name), "1"))
	log.Info("Enabled neighbour solicitation")

	// Enable ARP
	if err := netlink.LinkSetARPOn(link); err != nil {
		return err
	}

	// Split addr into component parts
	// > addr -> 10.0.0.2/24
	// > ip -> 10.0.0.2
	// > ipNet -> 10.0.0.0/24
	ip, ipNet, err := net.ParseCIDR(addr.String())
	if err != nil {
		return err
	}

	// Assign subnet (with *network* address) to dummy iface
	if err := AssignAddr(link, ipNet); err != nil {
		return err
	}

	// Bring up dummy interface
	if err := LinkEnable(link); err != nil {
		return err
	}

	// >>> ip link add wg0 type wireguard
	link, err = CreateDevice(RealIFName(n), WireGuardLinkType)
	if err != nil {
		return err
	}

	// Configure WireGuard Device
	// >>> wg set wg0 private-key /etc/wireguard/wg.key listen-port 51820
	if err := wg.Client.ConfigureDevice(link.Attrs().Name, c); err != nil {
		return err
	}
	log.WithFields(log.Fields{
		"dev": link.Attrs().Name,
	}).Info("Applied configuration to device")

	// Configure interface
	// >>> ip a a 10.0.0.2/24 dev wg0
	if err := AssignAddr(link, netlink.NewIPNet(ip)); err != nil {
		return err
	}

	// >>> ip link set up wg0
	return LinkEnable(link)
}

func (wg WireGuard) AddPeer(d string, c wgtypes.PeerConfig) error {
	// wg set wg0 peer tn8E8lypJhS0+lzw8pofl3w4Q+nRGb1x5j7RKG0Y0y4= endpoint 134.209.16.128:51820 allowed-ips 10.0.0.4/32
	return wg.Client.ConfigureDevice(d, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{c,},
		ReplacePeers: false,
	})
}
