package service

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/ontio/ontology-crypto/signature"
	"sort"
)

const ZionPublicKeyLength int = 33 // like: 023884de29148505a8d862992e5721767d4b47ff52ffab4c2d2527182d812a6d95

func recoverPublicKeys(pubKeys []byte) [][]byte {
	count := len(pubKeys) / ZionPublicKeyLength
	pubKeyArray := make([][]byte, count)
	for i := 0; i < count; i++ {
		pubKeyArray[i] = pubKeys[i*ZionPublicKeyLength : i*ZionPublicKeyLength+ZionPublicKeyLength]
	}
	return pubKeyArray
}

func recoverPublicKeyFromSignature(sig, hash []byte) ([]byte, error) {
	s, err := signature.Deserialize(sig)
	if err != nil {
		return nil, err
	}
	t, ok := s.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid signature type")
	}
	if len(t) != 65 {
		return nil, fmt.Errorf("invalid signature length")
	}

	pubKey, _, err := btcec.RecoverCompact(btcec.S256(), t, hash) // S256 is secp256k1, P256 is secp256r1,
	if err != nil {
		return nil, err
	}
	return pubKey.SerializeCompressed(), nil // length in 33
}

func sortPublicKeys(list []*ecdsa.PublicKey) []*ecdsa.PublicKey {
	pl := publicKeyList(list)
	sort.Sort(pl)
	return pl
}

type publicKeyList []*ecdsa.PublicKey

func (this publicKeyList) Len() int {
	return len(this)
}

func (this publicKeyList) Less(i, j int) bool {
	va, vb := this[i], this[j]
	cmp := va.X.Cmp(vb.X)
	if cmp != 0 {
		return cmp < 0
	}
	cmp = va.Y.Cmp(vb.Y)
	return cmp < 0
}

func (this publicKeyList) Swap(i, j int) {
	this[i], this[j] = this[j], this[i]
}

func sortSignatures(pubKeys, sigs [][]byte, hash []byte) ([]byte, error) {
	// sig length should >= 2/3 * len(pubKeys) + 1
	if len(sigs) < len(pubKeys)*2/3+1 {
		return nil, fmt.Errorf("not enough signatures")
	}
	sortedSigs := make([][]byte, len(pubKeys))
	//Log.Infof("before sorting sig: ")
	for _, sig := range sigs {
		//Log.Infof(helper.BytesToHex(sig))
		pubKey, err := recoverPublicKeyFromSignature(sig, hash) // sig in BTC format
		//Log.Infof(helper.BytesToHex(pubKey))
		if err != nil {
			return nil, fmt.Errorf("recoverPublicKeyFromSignature error: %s", err)
		}
		//newPubKey := append([]byte{0x12, 0x05}, pubKey...)
		//Log.Infof(helper.BytesToHex(newPubKey))
		index := -1
		for i, _ := range pubKeys {
			if bytes.Equal(pubKeys[i], pubKey) {
				index = i
				break
			}
		}
		if index == -1 {
			return nil, fmt.Errorf("signature (%s) recovered public key (%s) not found", helper.BytesToHex(sig), helper.BytesToHex(pubKey))
		}
		sortedSigs[index] = sig
	}
	sigListBytes := []byte{}
	//Log.Infof("sorted sig: ")
	for _, sortedSig := range sortedSigs {
		// convert to eth format
		if len(sortedSig) != 0 {
			//Log.Infof(helper.BytesToHex(sortedSig))
			newSig, _ := signature.ConvertToEthCompatible(sortedSig)
			sigListBytes = append(sigListBytes, newSig...)
		}
	}
	return sigListBytes, nil
}
