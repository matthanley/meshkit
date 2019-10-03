package main

import (
	"fmt"
	"net"

	"github.com/libp2p/go-libp2p-record"
)

const (
	MeshKitPrefix	= "ip4"
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

	keyAddr := net.ParseIP(key)
	if keyAddr == nil {
		return fmt.Errorf("IP address expected; got '%s'", key)
	}

	var v Peer
	if err := unbox(value, wg.Key, &v); err != nil {
		return err
	}

	if !keyAddr.Equal(v.Addr) {
		return fmt.Errorf("Key '%s' does not match payload Addr '%s'", key, v.Addr.String())
	}

	return nil
}

func (wg MeshKitValidator) Select(k string, vals [][]byte) (int, error) {
	return 0, nil
}
