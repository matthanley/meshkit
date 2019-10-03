package main

import (
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type NetlinkSubscription struct {
	Done		chan struct{}
	Channel		chan netlink.NeighUpdate
	L3Miss		func (netlink.Neigh) error
}

func NewNetlinkSubscription() (*NetlinkSubscription, error) {
	sub := &NetlinkSubscription{
		Done: make(chan struct{}),
		Channel: make(chan netlink.NeighUpdate),
		L3Miss: func (n netlink.Neigh) error {
			return nil
		},
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
