package main

import (
	"fmt"
	"net"

	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-record"
)

// TODO:
// Split validator into peer and ip{4,6} validators

const (
	MeshKitPrefix	= "peer"
)

type MeshKitValidator struct{
	Key [KeySize]byte
}

func (wg MeshKitValidator) Validate(key string, value []byte) error {
	ns, key, err := record.SplitKey(key)
	if err != nil {
		return err
	}
	if ns != MeshKitPrefix {
		return fmt.Errorf("'%s' namespace expected; got '%s'", MeshKitPrefix, ns)
	}

	// Check for an IP address in the key
	var keyID peer.ID
	keyAddr := net.ParseIP(key)
	if keyAddr == nil {
		// We don't have an IP address; check for a peer ID instead
		keyID, err = peer.IDB58Decode(key)
		if (err != nil) {
			return fmt.Errorf("IP address or Peer ID expected; got '%s'", key)
		}
	}

	var v Peer
	if err := unbox(value, wg.Key, &v); err != nil {
		return err
	}

	// by this point one of {keyAddr, keyID} is non-nil
	if keyAddr != nil {
		if !keyAddr.Equal(v.Addr) {
			return fmt.Errorf("Key '%s' does not match payload Addr '%s'", key, v.Addr.String())
		}
	} else if keyID != v.PeerID {
		return fmt.Errorf("Key '%s' does not match peer ID '%s'", key, v.PeerID.String())
	}

	return nil
}

func (wg MeshKitValidator) Select(k string, vals [][]byte) (int, error) {
	return 0, nil
}
