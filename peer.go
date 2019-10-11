package main

import (
	"context"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr-net"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Peer struct {
	PublicKey	wgtypes.Key		`json:"key"`
	PeerID		peer.ID			`json:"peer"`
	Port		int				`json:"port"`
	Addr		net.IP			`json:"addr"`
}

func resolvePeer(o interface{}, d *dht.IpfsDHT, k [KeySize]byte) (Peer, error) {
	var key string
	switch a := o.(type) {
	case net.IP:
		key = addrToDHTKey(a)
	case peer.ID:
		key = peerToDHTKey(a)
	default:
		return Peer{}, fmt.Errorf("Unknown peer reference")
	}

	log.WithFields(log.Fields{
		"key": key,
	}).Info("DHT lookup")

	// There's potential for a race here if we connect
	// before the peer entry has been populated in the DHT -
	// Keep looking for 10 seconds
	var result []byte

	loop:
		for timeout := time.After(time.Second*10); ; {
			select {
			case <-timeout:
				return Peer{}, fmt.Errorf("Deadline exceeded")
			default:
				var err error
				if result, err = d.GetValue(
					context.TODO(),
					key,
				); err != nil {
					// If it doesn't exist, keep looking until
					// timeout
					log.WithFields(log.Fields{
						"key": key,
					}).Debug("Not found; keep trying")
					break // break select
				}
				// Found peer - stop looking
				break loop // break for loop
			}
			time.Sleep(time.Second)
		}

	var p Peer
	if err := unbox(result, k, &p); err != nil {
		return Peer{}, err
	}
	log.WithFields(log.Fields{
		"key": key,
		"PublicKey": p.PublicKey.String(),
		"PeerID": p.PeerID.String(),
		"Port": p.Port,
		"Addr": p.Addr.String(),
	}).Info("GetValue")

	return p, nil
}

func (p Peer) advertise(d *dht.IpfsDHT, k [KeySize]byte) error {
	payload, err := box(p, k)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"addr": p.Addr.String(),
		"id": p.PeerID.String(),
	}).Info("Advertising overlay address")

	/*
		Peers need to be resolvable by both IP address and
		Peer ID, so we create the same entry with two keys
	 */

	// PutValue with PeerID as key
	if err := d.PutValue(
		context.TODO(),
		peerToDHTKey(p.PeerID),
		payload,
	); err != nil {
		return err
	}

	// PutValue with IP as key
	return d.PutValue(
		context.TODO(),
		addrToDHTKey(p.Addr),
		payload,
	)
}

func (p Peer) networkEndpoint(d *dht.IpfsDHT) (*net.UDPAddr, error) {
	// Locate the Peer on the network
	log.WithFields(log.Fields{
		"peer": p.PeerID.String(),
	}).Info("FindPeer in DHT")
	addrInfo, err := d.FindPeer(context.TODO(), p.PeerID)
	if err != nil {
		return &net.UDPAddr{}, err
	}

	log.WithFields(log.Fields{
		"peer": addrInfo.ID.String(),
		"addrs": addrInfo.Addrs,
	}).Info("Resolved peer addresses")

	/*
		Block until we successfully connect
	 */
	d.Host().Connect(context.TODO(), addrInfo)

	/*
		Get an *active* connection multiaddress -
		should ensure we have a reachable endpoint
		for the peer.
	 */
	activeConns := d.Host().Network().ConnsToPeer(p.PeerID)
	maddr := activeConns[0].RemoteMultiaddr()
	log.WithFields(log.Fields{
		"peer": p.PeerID.String(),
		"addr": maddr.String(),
	}).Info("Active multiaddress")

	if !manet.IsThinWaist(maddr) {
		return &net.UDPAddr{}, fmt.Errorf("Unexpected multiaddress format: %s", maddr.String())
	}
	netAddr, err := manet.ToNetAddr(maddr)
	if err != nil {
		return &net.UDPAddr{}, err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", netAddr.String())
	if err != nil {
		return &net.UDPAddr{}, err
	}

	if udpAddr.Port != p.Port {
		log.WithFields(log.Fields{
			"advertised": p.Port,
			"discovered": udpAddr.Port,
		}).Warn("Peer port mismatch; using advertised port")
		udpAddr.Port = p.Port
	}

	return udpAddr, nil
}

func (p Peer) toWireguardPeerConfig(d *dht.IpfsDHT) (wgtypes.PeerConfig, error) {
	endpoint, err := p.networkEndpoint(d)
	if err != nil {
		return wgtypes.PeerConfig{}, err
	}

	keepalive := Keepalive

	return wgtypes.PeerConfig {
		PublicKey: p.PublicKey,
		Endpoint: endpoint,
		PersistentKeepaliveInterval: &keepalive,
		AllowedIPs: []net.IPNet{
			*netlink.NewIPNet(p.Addr),
		},
	}, nil
}
