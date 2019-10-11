package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	opts "github.com/libp2p/go-libp2p-kad-dht/opts"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr"
	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/ed25519"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	DefaultPort		= 0xCAFE // 51966
	IFName			= "mesh0"
	Keepalive		= time.Hour
	TokenSeparator	= "!"
)

func ConfigureLocalDevice(a *net.IPNet, p *int, k *wgtypes.Key) error {
	// Config wg device
	wgClient := NewWireGuard()
	defer wgClient.Client.Close()

	if err := wgClient.CreateDevice(
		IFName, a,
		wgtypes.Config{
			PrivateKey: k,
			ListenPort: p,
		},
	); err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"if": IFName,
		"addr": a.String(),
		"pubkey": k.PublicKey().String(),
	}).Info("Configured local overlay endpoint")

	return nil
}

func CreatePeerFromDHT(o interface{}, d *dht.IpfsDHT, k [KeySize]byte) error {
	p, err := resolvePeer(o, d, k)
	if err != nil {
		return err
	}
	wgPeer, err := p.toWireguardPeerConfig(d)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"PublicKey": wgPeer.PublicKey,
		"Endpoint": wgPeer.Endpoint,
		"PersistentKeepaliveInterval": wgPeer.PersistentKeepaliveInterval,
		"AllowedIPs": wgPeer.AllowedIPs,
	}).Info("Resolved WireGuard peer config")

	wgClient := NewWireGuard()
	defer wgClient.Client.Close()

	if err := wgClient.AddPeer(RealIFName(IFName), wgPeer); err != nil {
		return err
	}

	// Add a route for the peer to our WireGuard iface
	link, err := netlink.LinkByName(RealIFName(IFName))
	if err != nil {
		return err
	}
	return RouteAddViaLink(netlink.NewIPNet(p.Addr), link)
}

func main() {
	debug := flag.Bool("debug", false,
		"Enable verbose output (insecure)")
	overlayAddress := flag.String("overlay-address", os.Getenv("OVERLAY_ADDRESS"),
		"IP address allocated in the overlay network")
	advertiseAddress := flag.String("advertise-address", os.Getenv("ADVERTISE_ADDRESS"),
		"IP address to advertise to peers")
	listenPort := flag.Int("port", DefaultPort,
		"Listen port")
	token := flag.String("token", "",
		"Join token")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	// Creates a new Ed25519 key pair for this host.
	dhtKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, ed25519.PrivateKeySize)
	panicOnErr(err)

	private, err := dhtKey.Raw()
	log.WithFields(log.Fields{
		"type": dhtKey.Type(),
		"length": len(private),
		"key": crypto.ConfigEncodeKey(private),
	}).Debug("Generated DHT keys")

	host, err := libp2p.New(
		context.Background(),
		// TODO: infer ip{4,6}
		libp2p.ListenAddrStrings(fmt.Sprintf(
			"/ip4/%s/tcp/%d",
			*advertiseAddress, // 0.0.0.0?
			*listenPort,
		)),
		libp2p.Identity(dhtKey),
	)
	panicOnErr(err)
	defer host.Close()

	log.WithFields(log.Fields{
		"host": host.ID(),
		"maddrs": host.Addrs(),
	}).Info("Host created")

	// Mesh-wide key for encrypting DHT entries
	var meshKey [KeySize]byte

	var bootstrapPeer *peer.AddrInfo

	if *token != "" {
		tokenString, err := base64.StdEncoding.DecodeString(*token)
		panicOnErr(err)

		// Unpack tokenString
		decodedToken := strings.Split(string(tokenString), TokenSeparator)

		peerAddr, err := multiaddr.NewMultiaddr(decodedToken[0])
		panicOnErr(err)

		addrInfo, err := peer.AddrInfoFromP2pAddr(peerAddr)
		panicOnErr(err)
		bootstrapPeer = addrInfo

		// Load key from token
		loadedKey, err := crypto.ConfigDecodeKey(decodedToken[1])
		panicOnErr(err)
		copy(meshKey[:], loadedKey)
	} else {
		// Create a new key
		if _, err := io.ReadFull(rand.Reader, meshKey[:]); err != nil {
			warnOnErr(err)
		}
		log.WithFields(log.Fields{
			"key": crypto.ConfigEncodeKey(meshKey[:]),
		}).Info("Generated shared mesh key")
	}

	// init DHT
	data, err := dht.New(
		context.Background(),
		host,
		opts.NamespacedValidator(
			MeshKitPrefix,
			MeshKitValidator{
				Key: meshKey,
			},
		),
	)
	defer data.Close()
	panicOnErr(err)

	// Create Wireguard Keys
	wgKey, err := wgtypes.GeneratePrivateKey()
	panicOnErr(err)

	log.WithFields(log.Fields{
		"key": wgKey.String(),
		"pub": wgKey.PublicKey().String(),
	}).Debug("Generated network keys")

	// Create WireGuard interface
	meshAddr, err := netlink.ParseIPNet(*overlayAddress)
	panicOnErr(err)

	panicOnErr(ConfigureLocalDevice(meshAddr, listenPort, &wgKey))

	// Tidy up after ourselves
	defer func () {
		warnOnErr(DestroyDevice(IFName))
		warnOnErr(DestroyDevice(RealIFName(IFName)))
		log.Info(">>> Shutting down.")
	}()

	host.Network().SetConnHandler(
		func (conn network.Conn) {
			warnOnErr(CreatePeerFromDHT(conn.RemotePeer(), data, meshKey))
		},
	)

	host.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, c network.Conn) {
			log.WithFields(log.Fields{
				"peer": c.RemotePeer().String(),
				"addr": c.RemoteMultiaddr().String(),
			}).Info("Peer connected")

			/*
				There appears to be a bug in libp2p that
				causes the TTL of entries in the peerstore
				to expire even while peers are still connected.
				This corrects that behaviour.
			 */
			host.Peerstore().AddAddrs(
				c.RemotePeer(),
				[]multiaddr.Multiaddr{c.RemoteMultiaddr()},
				peerstore.ConnectedAddrTTL,
			)
		},
		DisconnectedF: func(n network.Network, c network.Conn) {
			log.WithFields(log.Fields{
				"peer": c.RemotePeer().String(),
			}).Info("Peer disconnected")

			host.Peerstore().UpdateAddrs(
				c.RemotePeer(),
				peerstore.ConnectedAddrTTL,
				peerstore.RecentlyConnectedAddrTTL,
			)

			// TODO: Remove the WG peer info
		},
	})

	// Bootstrap from other peer
	if bootstrapPeer != nil {
		warnOnErr(host.Connect(context.TODO(), *bootstrapPeer))
	}

	// Bootstrap complete
	log.WithFields(log.Fields{
		"token": joinToken(host, meshKey),
	}).Info(">>> Join token <<<")

	// Only advertise when we have peers available
	log.Info("Waiting for peers")
	for data.RoutingTable().Size() == 0 {
		time.Sleep(time.Second)
	}

	warnOnErr(Peer{
		PublicKey: wgKey.PublicKey(),
		PeerID: host.ID(),
		Port: *listenPort,
		Addr: meshAddr.IP,
	}.advertise(data, meshKey))

	// Set handler for RTM_GETNEIGH
	link, err := netlink.LinkByName(IFName)
	panicOnErr(err)

	_, err = NewNetlinkSubscription(
		link,
		func (n netlink.Neigh) error {
			log.WithFields(log.Fields{
				"addr": n.IP.String(),
			}).Info("Received L3Miss from netlink")
			return CreatePeerFromDHT(n.IP, data, meshKey)
		},
	)
	panicOnErr(err)

	// Run indefinitely
	select {}
}

// TODO
// - Infer advertiseAddress if nInterfaces == 1
// - Remove stale connections
// 		detect packet loss/unreachable from netlink?
// 		connection timeout? (latest handshake > keepalive)
// - Persist config/DHT state
// 		leveldb?
// - IPAM (raft?)
