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
	"time"

	log "github.com/sirupsen/logrus"
	opts "github.com/libp2p/go-libp2p-kad-dht/opts"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr"
	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/ed25519"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	DefaultPort		= 0xCAFE // 51966
	IFName			= "meshk0"
	Keepalive		= time.Hour
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

func CreatePeerFromDHT(a net.IP, d *dht.IpfsDHT, k [KeySize]byte) error {
	peer, err := resolvePeerFromAddr(a, d, k)
	if err != nil {
		return err
	}
	wgPeer, err := peer.toWireguardPeerConfig(d)
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

	return wgClient.AddPeer(IFName, wgPeer)
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

	// Create Wireguard Keys
	wgKey, err := wgtypes.GeneratePrivateKey()
	panicOnErr(err)

	log.WithFields(log.Fields{
		"key": wgKey.String(),
		"pub": wgKey.PublicKey().String(),
	}).Debug("Generated network keys")

	// Create a mesh-wide key for encrypting DHT entries
	var meshKey [KeySize]byte
	if _, err := io.ReadFull(rand.Reader, meshKey[:]); err != nil {
		warnOnErr(err)
	}

	// TODO: load key from token if exists
	// loadedKey, _ := crypto.ConfigDecodeKey("Sju02mQ8GJDcd1sxpW5D0Ru7fia+RF5pZw2b1ubWtDg=")
	// copy(meshKey[:], loadedKey)

	log.WithFields(log.Fields{
		"key": crypto.ConfigEncodeKey(meshKey[:]),
	}).Info("Generated shared mesh key")

	host, err := libp2p.New(
		context.Background(),
		// TODO: infer ip{4,6}
		libp2p.ListenAddrStrings(fmt.Sprintf(
			"/ip4/%s/tcp/%d",
			*advertiseAddress,
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

	log.WithFields(log.Fields{
		"token": joinToken(host),
	}).Info(">>> Join token <<<")

	// Create WireGuard interface
	meshAddr, err := netlink.ParseIPNet(*overlayAddress)
	panicOnErr(err)

	panicOnErr(ConfigureLocalDevice(meshAddr, listenPort, &wgKey))

	// Tidy up after ourselves
	defer func () {
		warnOnErr(DestroyDevice(IFName))
		log.Info(">>> Shutting down.")
	}()

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

	panicOnErr(data.Bootstrap(data.Context()))

	host.Network().SetConnHandler(
		func (conn network.Conn) {
			log.WithFields(log.Fields{
				"peer": conn.RemotePeer().String(),
				"addr": conn.RemoteMultiaddr().String(),
			}).Info("Peer connected")
		},
	)

	// Bootstrap from other peer
	if *token != "" {
		decodedToken, err := base64.StdEncoding.DecodeString(*token)
		panicOnErr(err)

		peerAddr, err := multiaddr.NewMultiaddr(string(decodedToken))
		panicOnErr(err)

		addrInfo, err := peer.AddrInfoFromP2pAddr(peerAddr)
		panicOnErr(err)

		if err := host.Connect(context.TODO(), *addrInfo); err != nil {
			warnOnErr(err)
		}
	}

	warnOnErr(Peer{
		PublicKey: wgKey.PublicKey(),
		PeerID: host.ID(),
		Port: *listenPort,
		Addr: meshAddr.IP,
	}.advertise(data, meshKey))

	netlinkSub, err := NewNetlinkSubscription()
	panicOnErr(err)

	// Set handler for RTM_GETNEIGH
	netlinkSub.L3Miss = func (n netlink.Neigh) error {
		return CreatePeerFromDHT(n.IP, data, meshKey)
	}

	// Run indefinitely
	select {}
}

// TODO
// - Include meshKey in joinToken
// - NETLINK listener
// 		Fix required for WireGuard interfaces :(
// - Remove stale connections
// 		detect packet loss/unreachable from netlink?
// 		connection timeout? (latest handshake > keepalive)
// - Persist config/DHT state
// 		leveldb?
// - IPAM (raft?)
// - Infer advertiseAddress if nInterfaces == 1
