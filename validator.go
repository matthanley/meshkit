package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/libp2p/go-libp2p-record"
)

const (
	WireguardPrefix	= "ip4"
)

type WireguardValidator struct{
	Key [KeySize]byte
}

func (wg WireguardValidator) Validate(key string, value []byte) error {
	ns, key, err := record.SplitKey(key)
	if err != nil {
		return err
	}
	if ns != WireguardPrefix {
		return fmt.Errorf("'%s' namespace expected; got '%s'", WireguardPrefix, ns)
	}

	keyAddr := net.ParseIP(key)
	if keyAddr == nil {
		return fmt.Errorf("IP address expected; got '%s'", key)
	}

	var v Peer
	if err := unbox(value, wg.Key, &v); err != nil {
		return errors.New("Expected object <Peer>")
	}

	if !keyAddr.Equal(v.Addr) {
		return fmt.Errorf("Key '%s' does not match payload Addr '%s'", key, v.Addr.String())
	}

	return nil
}

func (wg WireguardValidator) Select(k string, vals [][]byte) (int, error) {
	return 0, nil
}
