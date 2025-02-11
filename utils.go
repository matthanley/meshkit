package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	KeySize			= 32
	NonceLength		= 24
)

func box(c interface{}, k [KeySize]byte) ([]byte, error) {
	// Serialize our object
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	// Generate a nonce
	var nonce [NonceLength]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	// Encrypt
	return secretbox.Seal(nonce[:], b, &nonce, &k), nil
}

func unbox(b []byte, k [KeySize]byte, c interface{}) error {
	log.WithFields(log.Fields{
		"payload": toBase64(b[:]),
	}).Debug("Unboxing payload")
	// Extract nonce from payload
	var nonce [NonceLength]byte
	copy(nonce[:], b[:NonceLength])
	// Decrypt payload
	decrypted, ok := secretbox.Open(nil, b[NonceLength:], &nonce, &k)
	if !ok {
		return errors.New("Decryption error")
	}
	return json.Unmarshal(decrypted, &c)
}

func addrToDHTKey(a net.IP) string {
	return fmt.Sprintf("/%s/%s", MeshKitPrefix, a.String())
}

func peerToDHTKey(p peer.ID) string {
	return fmt.Sprintf("/%s/%s", MeshKitPrefix, p.String())
}

func toBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func stringToBase64(s string) string {
	return toBase64([]byte(s))
}

func joinToken(h host.Host, k [KeySize]byte) string {
	addrs := h.Addrs()
	return stringToBase64(fmt.Sprintf(
		"%s/p2p/%s%s%s",
		addrs[0],
		h.ID(),
		TokenSeparator,
		crypto.ConfigEncodeKey(k[:]),
	))
}

func warnOnErr(err error) {
	if err != nil {
		log.Warn(err.Error())
	}
}

func panicOnErr(err error) {
	if err != nil {
		log.Error(err.Error())
	}
}
