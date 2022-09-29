package client

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func loadKeyFromBytes(keyBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("Error decoding key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// TODO: support v3 keys as well - above supports v2, below v3
	// key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	// if err != nil {
	// 	return nil, err
	// }

	// if key, ok := key.(crypto.PrivateKey); ok {
	// 	return key, nil
	// } else {
	// 	return nil, fmt.Errorf("invalid private key")
	// }

	return key, nil
}

func loadKeyFromString(keyString string) (crypto.PrivateKey, error) {
	return loadKeyFromBytes([]byte(keyString))
}

func loadKeyFromFile(filename string) (crypto.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return loadKeyFromBytes(bytes)
}
