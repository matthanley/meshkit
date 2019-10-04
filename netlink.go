package main

import (
	"net"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type NetlinkSubscription struct {
	Done		chan struct{}
	Channel		chan netlink.NeighUpdate
	L3Miss		func (netlink.Neigh) error
}

func NewNetlinkSubscription(h func (netlink.Neigh) error) (*NetlinkSubscription, error) {
	sub := &NetlinkSubscription{
		Done: make(chan struct{}),
		Channel: make(chan netlink.NeighUpdate),
		L3Miss: h,
	}

	if err := netlink.NeighSubscribe(sub.Channel, sub.Done); err != nil {
		close(sub.Channel)
		close(sub.Done)
		return sub, err
	}

	go sub.handle()

	return sub, nil
}

// unix.RTM_GETNEIGH 0x1e 30
// 		netlink.NUD_INCOMPLETE = 0x01  1
// unix.RTM_NEWNEIGH 0x1c 28
// 		netlink.NUD_REACHABLE  = 0x02  2
// 		netlink.NUD_STALE      = 0x04  4
// 		netlink.NUD_PROBE      = 0x10 16
// 		netlink.NUD_FAILED     = 0x20 32

func (s NetlinkSubscription) handle() {
	defer close(s.Done)
	for {
		update := <-s.Channel
		switch t := update.Type; t {
		case unix.RTM_GETNEIGH:
			warnOnErr(s.L3Miss(update.Neigh))
		default:
			//
		}
	}
}

func LinkEnable(link netlink.Link) error {
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	log.WithFields(log.Fields{
		"dev": link.Attrs().Name,
	}).Info("Interface UP")
	return nil
}

func AssignAddr(link netlink.Link, addr *net.IPNet) error {
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
		"dev": link.Attrs().Name,
	}).Info("Added IP address to interface")

	return nil
}

func RouteAddViaLink(r *net.IPNet, link netlink.Link) error {
	route := &netlink.Route{
		Dst: r,
		LinkIndex: link.Attrs().Index,
	}

	return netlink.RouteAdd(route)
}

func CreateDevice(n string, t string) (netlink.Link, error) {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = n

	if err := netlink.LinkAdd(
		&netlink.GenericLink{
			LinkAttrs: attrs,
			LinkType: t,
		},
	); err != nil {
		// If iface already exists, move along
		if !os.IsExist(err) {
			return nil, err
		}
		log.WithFields(log.Fields{
			"dev": n,
		}).Warn("Device already exists; settings may get overridden")
	}

	// Populate a Link from netlink
	link, err := netlink.LinkByName(n)
	if err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{
		"dev": link.Attrs().Name,
		"type": link.Type(),
	}).Info("Created netlink device")

	return link, nil
}

func DestroyDevice(n string) error {
	link, err := netlink.LinkByName(n)
	if err != nil {
		if os.IsNotExist(err) {
			// Nothing to do
			return nil
		}
		return err
	}
	return netlink.LinkDel(link)
}
