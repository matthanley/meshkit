package main

import (
	"context"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr-net"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Peer struct {
	PublicKey	wgtypes.Key
	PeerID		peer.ID
	Port		int
	Addr		net.IP
}

func resolvePeerFromAddr(addr net.IP, d *dht.IpfsDHT, k [KeySize]byte) (Peer, error) {
	result, err := d.GetValue(
		context.TODO(),
		addrToDHTKey(addr),
	)
	if err != nil {
		return Peer{}, err
	}

	var p Peer
	if err := unbox(result, k, &p); err != nil {
		return Peer{}, err
	}
	log.WithFields(log.Fields{
		"key": addrToDHTKey(p.Addr),
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
	}).Info("Advertising overlay address")
	return d.PutValue(
		context.TODO(),
		addrToDHTKey(p.Addr),
		payload,
	)
}

func (p Peer) networkEndpoint(d *dht.IpfsDHT) (*net.UDPAddr, error) {
	// Locate the Peer on the network
	addrInfo, err := d.FindPeer(context.TODO(), p.PeerID)
	if err != nil {
		return &net.UDPAddr{}, err
	}

	log.WithFields(log.Fields{
		"peer": addrInfo.ID.String(),
		"addrs": addrInfo.Addrs,
	}).Info("Resolved peer addresses")

	// Block until we successfully connect
	d.Host().Connect(context.TODO(), addrInfo)

	// Get active connection multiaddress
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
			net.IPNet{
				IP: p.Addr,
				// TODO: IPv6 support
				Mask: net.CIDRMask(32, 32),
			},
		},
	}, nil
}
