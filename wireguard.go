package main

import (
	"fmt"
	"net"
	"os"

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
	WireGuardLinkType		= "wireguard"
)

func NewWireGuard() *WireGuard {
	client, err := wgctrl.New()
	panicOnErr(err)

	return &WireGuard{
		Client: *client,
	}
}

func (wg WireGuard) CreateDevice(n string, addr *net.IPNet, c wgtypes.Config) error {
	attrs := netlink.NewLinkAttrs()
    attrs.Name = n

	// >>> ip link add wg0 type wireguard
	if err := netlink.LinkAdd(
		&netlink.GenericLink{
			LinkAttrs: attrs,
			LinkType: WireGuardLinkType,
		},
	); err != nil {
		// If iface already exists, move along
		if !os.IsExist(err) {
			return err
		}
		log.WithFields(log.Fields{
			"dev": n,
		}).Warn("Device already exists; settings may get overridden")
	}

	// Populate a Link from netlink
	link, err := netlink.LinkByName(n)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"dev": link.Attrs().Name,
		"type": link.Type(),
	}).Info("Created netlink device")

	// Enable broadcasting of RTM_GETNEIGH messages
	warnOnErr(sysctl.Set(fmt.Sprintf("net.ipv4.neigh.%s.app_solicit", n), "1"))
	log.Info("Enabled neighbour solicitation")

	// Configure WireGuard Device
	// >>> wg set wg0 private-key /etc/wireguard/wg.key listen-port 51820
	if err := wg.Client.ConfigureDevice(n, c); err != nil {
		return err
	}
	log.WithFields(log.Fields{
		"dev": n,
	}).Info("Applied configuration to device")

	// Configure interface
	// >>> ip a a 10.0.0.2/24 dev wg0
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: addr}); err != nil {
		if !os.IsExist(err) {
			log.WithFields(log.Fields{
				"link": link,
				"addr": addr,
			}).Warn("Failed adding address to interface")
			return err
		}
		log.WithFields(log.Fields{
			"link": link,
			"addr": addr,
		}).Warn("Address already exists on device")
	}
	log.WithFields(log.Fields{
		"addr": addr.String(),
		"dev": n,
	}).Info("Added IP address to interface")

	// >>> ip link set up wg0
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	log.WithFields(log.Fields{
		"dev": n,
	}).Info("Interface UP")

	return nil
}

func (wg WireGuard) AddPeer(d string, c wgtypes.PeerConfig) error {
	// wg set wg0 peer tn8E8lypJhS0+lzw8pofl3w4Q+nRGb1x5j7RKG0Y0y4= endpoint 134.209.16.128:51820 allowed-ips 10.0.0.4/32
	return wg.Client.ConfigureDevice(d, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{c,},
		ReplacePeers: false,
	})
}
