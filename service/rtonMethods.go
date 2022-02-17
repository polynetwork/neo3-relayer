package service

import (
	"bytes"
	goc "crypto"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/joeqian10/neo3-gogogo/crypto"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/joeqian10/neo3-gogogo/rpc/models"
	"github.com/joeqian10/neo3-gogogo/sc"
	"github.com/joeqian10/neo3-gogogo/tx"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology-crypto/sm2"
	"github.com/polynetwork/neo3-relayer/db"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/types"
	"strings"
	"time"

	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
)

const (
	VERIFY_AND_EXECUTE_TX = "verifyAndExecuteTx"
	CHANGE_BOOK_KEEPER    = "changeBookKeeper"
	GET_BOOK_KEEPERS      = "getBookKeepers"
)

// GetCurrentNeoChainSyncHeight
func (this *SyncService) GetCurrentNeoChainSyncHeight() (uint64, error) {
	response := this.neoSdk.GetStorage(this.config.NeoConfig.CCMC, "AgE=")
	if response.HasError() {
		return 0, fmt.Errorf("[GetCurrentNeoChainSyncHeight] GetStorage error: %s", response.GetErrorInfo())
	}
	var height uint64
	s := response.Result
	if s == "" {
		return 0, nil
	}
	b, err := crypto.Base64Decode(s)
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		height = 0
	} else {
		height = helper.BytesToUInt64(b)
		height++ // means the next block header needs to be synced
	}
	return height, nil
}

func (this *SyncService) changeBookKeeper(block *types.Block) error {
	headerBytes := block.Header.GetMessage()
	// raw header
	cp1 := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: headerBytes,
	}
	Log.Infof("raw header: %s", helper.BytesToHex(headerBytes))

	// public keys
	bs := []byte{}
	blkInfo := &vconfig.VbftBlockInfo{}
	_ = json.Unmarshal(block.Header.ConsensusPayload, blkInfo) // already checked before
	if blkInfo.NewChainConfig != nil {
		var bookkeepers []keypair.PublicKey
		for _, peer := range blkInfo.NewChainConfig.Peers {
			keyBytes, _ := hex.DecodeString(peer.ID)
			key, _ := keypair.DeserializePublicKey(keyBytes) // compressed
			bookkeepers = append(bookkeepers, key)
		}

		//// unsorted pub keys----------------------------------------
		//for _, pubKey := range bookkeepers {
		//	uncompressed := getRelayUncompressedKey(pubKey) // length 67
		//	bs = append(bs, uncompressed...)
		//}
		//Log.Infof("unsorted pub keys: %s", helper.BytesToHex(bs))
		////bs = []byte{}
		//// ---------------------------------------------------------

		// sort the new public keys
		bookkeepers = keypair.SortPublicKeys(bookkeepers)
		for _, pubKey := range bookkeepers {
			uncompressed := getRelayUncompressedKey(pubKey) // length 67
			//Log.Infof(helper.BytesToHex(uncompressed)) // sorted
			bs = append(bs, uncompressed...)
		}
		Log.Infof("sorted pub keys: %s", helper.BytesToHex(bs))
	}
	cp2 := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: bs,
	}

	// signatures
	var bs2 []byte
	if len(block.Header.SigData) == 0 {
		bs2 = []byte{}
	} else {
		var err error
		headerHash := block.Header.Hash()
		hasher := goc.SHA256.New()
		hasher.Write(headerHash.ToArray())
		digest := hasher.Sum(nil)
		bs2, err = this.sortSignatures(block.Header.SigData, digest)
		if err != nil {
			return fmt.Errorf("[changeBookKeeper] sort signatures error: %s", err)
		}
	}
	cp3 := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: bs2,
	}
	Log.Infof("signature: %s", helper.BytesToHex(bs2))

	// build script
	scriptHash, err := helper.UInt160FromString(this.config.NeoConfig.CCMC) // "0x" prefixed hex string in big endian
	if err != nil {
		return fmt.Errorf("[changeBookKeeper] neo ccmc conversion error: %s", err)
	}
	script, err := sc.MakeScript(scriptHash, CHANGE_BOOK_KEEPER, []interface{}{cp1, cp2, cp3})
	if err != nil {
		return fmt.Errorf("[changeBookKeeper] sc.MakeScript error: %s", err)
	}

	Log.Infof("script: " + crypto.Base64Encode(script))

	// make transaction
	balancesGas, err := this.nwh.GetAccountAndBalance(tx.GasToken)
	if err != nil {
		return fmt.Errorf("[changeBookKeeper] WalletHelper.GetAccountAndBalance error: %s", err)
	}
	trx, err := this.nwh.MakeTransaction(script, nil, []tx.ITransactionAttribute{}, balancesGas)
	if err != nil {
		return fmt.Errorf("[changeBookKeeper] WalletHelper.MakeTransaction error: %s", err)
	}

	// sign transaction
	trx, err = this.nwh.SignTransaction(trx, this.config.NeoConfig.NeoMagic)
	if err != nil {
		return fmt.Errorf("[changeBookKeeper] WalletHelper.SignTransaction error: %s", err)
	}
	rawTxString := crypto.Base64Encode(trx.ToByteArray())
	Log.Infof(rawTxString)

	// send the raw transaction
	response := this.neoSdk.SendRawTransaction(rawTxString)
	if response.HasError() {
		return fmt.Errorf("[] SendRawTransaction error: %s, "+
			"unsigned header hex string: %s, "+
			"public keys hex string: %s, "+
			"signatures hex string: %s"+
			"script hex string: %s, "+
			"changeBookKeeper RawTransactionString: %s",
			response.ErrorResponse.Error.Message,
			helper.BytesToHex(headerBytes),
			helper.BytesToHex(bs),
			helper.BytesToHex(bs2),
			helper.BytesToHex(script),
			rawTxString)
	}

	Log.Infof("[changeBookKeeper] txHash is: %s", trx.GetHash().String())

	return nil
}

func (this *SyncService) syncProofToNeo(height uint32, id []byte, subject []byte, sigData [][]byte) error {
	toMerkleValue, err := DeserializeMerkleValue(subject)
	if err != nil {
		return fmt.Errorf("DeserializeMerkleValue error: %s", err)
	}
	polyHash := helper.BytesToHex(toMerkleValue.TxHash)

	// check poly to neo contract
	if this.config.NeoConfig.P2NContract != "" {
		got := "0x" + helper.BytesToHex(helper.ReverseBytes(toMerkleValue.TxParam.ToContract)) // little endian
		expected := this.config.NeoConfig.P2NContract // big endian
		if got != expected {
			Log.Infof("This cross chain tx is not for this specific contract.")
			Log.Infof("expected toContract: " + expected + ", but got: " + got)
			return nil
		}
	}
	// limit the method to "unlock"
	if this.IsAllowedMethod(string(toMerkleValue.TxParam.Method)) {
		return fmt.Errorf("called method %s is invalid", helper.BytesToHex(toMerkleValue.TxParam.Method))
	}

	// check id == sha256.Sum256(subject)
	hasher := goc.SHA256.New()
	hasher.Write(subject)
	digest := hasher.Sum(nil)
	if bytes.Compare(id, digest) != 0 {
		return fmt.Errorf("incorrect id: %s for toMerkleValue: %s", helper.BytesToHex(id), helper.BytesToHex(subject))
	}
	crossInfo := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: subject,
	}

	// sort sigs
	signListBytes, err := this.sortSignatures(sigData, digest)
	if err != nil {
		return fmt.Errorf("sort signatures error: %s", err)
	}
	signList := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: signListBytes,
	}

	// build script
	scriptHash, err := helper.UInt160FromString(this.config.NeoConfig.CCMC)
	if err != nil {
		return fmt.Errorf("neo ccmc conversion error: %s", err)
	}
	script, err := sc.MakeScript(scriptHash, VERIFY_AND_EXECUTE_TX, []interface{}{crossInfo, signList})
	if err != nil {
		return fmt.Errorf("sc.MakeScript error: %s", err)
	}
	//Log.Infof("script: " + helper.BytesToHex(script))
	balancesGas, err := this.nwh.GetAccountAndBalance(tx.GasToken)
	if err != nil {
		return fmt.Errorf("WalletHelper.GetAccountAndBalance error: %s", err)
	}

	retry := &db.Retry{
		Height: height,
		TxHash: polyHash,
		Id: id,
		Subject: subject,
	}
	sink := common.NewZeroCopySink(nil)
	retry.Serialization(sink)
	v := sink.Bytes()

	neoTrx, err := this.nwh.MakeTransaction(script, nil, []tx.ITransactionAttribute{}, balancesGas)
	if err != nil {
		if strings.Contains(err.Error(), "insufficient GAS") {
			err = this.db.PutNeoRetry(v) // this tx is not ready thus will not cost extra gas, so put it into retry
			if err != nil {
				return fmt.Errorf("this.db.PutNeoRetry error: %s", err)
			}
			Log.Infof("insufficient GAS, put tx into retry db, height %d, polyHash %s, db key %s", height, polyHash, helper.BytesToHex(v))
			return nil
		}
		return fmt.Errorf("WalletHelper.MakeTransaction error: %s", err)
	}

	// sign transaction
	neoTrx, err = this.nwh.SignTransaction(neoTrx, this.config.NeoConfig.NeoMagic)
	if err != nil {
		return fmt.Errorf("WalletHelper.SignTransaction error: %s", err)
	}
	rawTxString := crypto.Base64Encode(neoTrx.ToByteArray())
	//Log.Infof("rawTxString: " + rawTxString)

	// send the raw transaction
	response := this.neoSdk.SendRawTransaction(rawTxString)
	if response.HasError() {
		return fmt.Errorf("SendRawTransaction error: %s, "+
			"script hex string: %s, "+
			"raw tx string: %s",
			response.GetErrorInfo(),
			helper.BytesToHex(script),
			rawTxString)
	}
	neoHash := neoTrx.GetHash().String()
	Log.Infof("syncProofToNeo txHash is: %s", neoHash)
	err = this.db.PutNeoCheck(neoHash, v)
	if err != nil {
		return fmt.Errorf("this.db.PutNeoCheck error: %s", err)
	}

	return nil
}

func (this *SyncService) retrySyncProofToNeo(v []byte) error {
	// deserialize retry to get cross chain info
	retry := new(db.Retry)
	err := retry.Deserialization(common.NewZeroCopySource(v))
	if err != nil {
		return fmt.Errorf("retry.Deserialization error: %s", err)
	}
	height := retry.Height
	id := retry.Id
	subject := retry.Subject

	toMerkleValue, err := DeserializeMerkleValue(subject)
	if err != nil {
		return fmt.Errorf("DeserializeMerkleValue error: %s", err)
	}
	polyHash := helper.BytesToHex(toMerkleValue.TxHash)
	// limit the method to "unlock"
	if this.IsAllowedMethod(string(toMerkleValue.TxParam.Method)) {
		return fmt.Errorf("called method %s is invalid", helper.BytesToHex(toMerkleValue.TxParam.Method))
	}

	Log.Infof("retrying old tx: %s at height %d", polyHash, height)

	polyTx, err := this.polySdk.GetTransaction(polyHash)
	if err != nil {
		return fmt.Errorf("GetTransaction error: %s", err)
	}
	if len(polyTx.Sigs) <= 0 {
		return fmt.Errorf("tx: %s has no sigs", polyHash)
	}
	sigData := polyTx.Sigs[0].SigData

	// check id == sha256.Sum256(subject)
	hasher := goc.SHA256.New()
	hasher.Write(subject)
	digest := hasher.Sum(nil)
	if bytes.Compare(id, digest) != 0 {
		return fmt.Errorf("incorrect id: %s for toMerkleValue: %s", helper.BytesToHex(id), helper.BytesToHex(subject))
	}
	crossInfo := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: subject,
	}

	// sort sigs
	signListBytes, err := this.sortSignatures(sigData, digest)
	if err != nil {
		return fmt.Errorf("sort signatures error: %s", err)
	}
	signList := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: signListBytes,
	}

	// build script
	scriptHash, err := helper.UInt160FromString(this.config.NeoConfig.CCMC)
	if err != nil {
		return fmt.Errorf("neo ccmc conversion error: %s", err)
	}
	script, err := sc.MakeScript(scriptHash, VERIFY_AND_EXECUTE_TX, []interface{}{crossInfo, signList})
	if err != nil {
		return fmt.Errorf("sc.MakeScript error: %s", err)
	}
	//Log.Infof("script: " + helper.BytesToHex(script))
	balancesGas, err := this.nwh.GetAccountAndBalance(tx.GasToken)
	if err != nil {
		return fmt.Errorf("WalletHelper.GetAccountAndBalance error: %s", err)
	}

	neoTrx, err := this.nwh.MakeTransaction(script, nil, []tx.ITransactionAttribute{}, balancesGas)
	if err != nil {
		return fmt.Errorf("WalletHelper.MakeTransaction error: %s", err)
	}

	// sign transaction
	neoTrx, err = this.nwh.SignTransaction(neoTrx, this.config.NeoConfig.NeoMagic)
	if err != nil {
		return fmt.Errorf("WalletHelper.SignTransaction error: %s", err)
	}
	rawTxString := crypto.Base64Encode(neoTrx.ToByteArray())
	//Log.Infof("rawTxString: " + rawTxString)

	// send the raw transaction
	response := this.neoSdk.SendRawTransaction(rawTxString)
	if response.HasError() {
		return fmt.Errorf("SendRawTransaction error: %s, "+
			"script hex string: %s, "+
			"raw tx string: %s",
			response.GetErrorInfo(),
			helper.BytesToHex(script),
			rawTxString)
	}
	neoHash := neoTrx.GetHash().String()

	Log.Infof("retrySyncProofToNeo txHash is: %s", neoHash)
	err = this.db.PutNeoCheck(neoHash, v)
	if err != nil {
		return fmt.Errorf("this.db.PutNeoCheck error: %s", err)
	}
	err = this.db.DeleteNeoRetry(v)
	if err != nil {
		return fmt.Errorf("this.db.DeleteNeoRetry error: %s", err)
	}
	return nil
}

func (this *SyncService) neoCheckTx() error {
	checkMap, err := this.db.GetNeoAllCheck()
	if err != nil {
		return fmt.Errorf("this.db.GetNeoAllCheck error: %s", err)
	}
	for k, v := range checkMap {
		retry := new(db.Retry)
		err := retry.Deserialization(common.NewZeroCopySource(v))
		if err != nil {
			return fmt.Errorf("retry.Deserialization error: %s", err)
		}

		// start check tx
		res := this.neoSdk.GetApplicationLog(k)
		if res.HasError() {
			info := res.GetErrorInfo()
			if !strings.Contains(info, "Unknown transaction/blockhash") {
				Log.Errorf("this.neoSdk.GetApplicationLog error: %s, txHash: %s", res.GetErrorInfo(), k)
			}
			continue
		}
		// can delete check now
		err = this.db.DeleteNeoCheck(k)
		if err != nil {
			return fmt.Errorf("this.db.DeleteNeoCheck error: %s", err)
		}
		appLog := res.Result
		if len(appLog.Executions) < 1 {
			Log.Errorf("this.neoSdk.GetApplicationLog error: no executions, txHash: %s", k)
			continue
		}
		exec := appLog.Executions[0]
		if exec.VMState == "FAULT" {
			Log.Errorf("tx engine faulted, neoHash: %s, polyHash: %s at height %d, exception: %s", k, retry.TxHash, retry.Height, exec.Exception)
			continue
		}
		if len(exec.Stack) < 1 {
			Log.Errorf("this.neoSdk.GetApplicationLog error: no stack result, txHash: %s", k)
			continue
		}
		stack := exec.Stack[0]
		if stack.Type == "Boolean" {
			b := stack.Value.(bool)
			if b == false {
				notifications := exec.Notifications
				if !appLogNotificationContains(notifications, this.config.NeoConfig.CCMC, "Transaction has been executed") { // if executed, skip
					Log.Errorf("tx stack result is false, neoHash: %s, polyHash: %s at height %d, check app log details and retry", k, retry.TxHash, retry.Height)
				}
				continue
			}
		}
		Log.Infof("tx is successful, hash: %s, polyHash: %s at height %d", k, retry.TxHash, retry.Height)
	}
	return nil
}

func (this *SyncService) neoRetryTx() error {
	retryList, err := this.db.GetAllNeoRetry()
	if err != nil {
		return fmt.Errorf("this.db.GetAllRetry error: %s", err)
	}
	for _, v := range retryList {
		retry := new(db.Retry)
		err := retry.Deserialization(common.NewZeroCopySource(v))
		if err != nil {
			return fmt.Errorf("retry.Deserialization error: %s", err)
		}

		err = this.retrySyncProofToNeo(v)
		if err != nil {
			Log.Errorf("this.retrySyncProofToNeo error:%s", err)
		}
		time.Sleep(time.Duration(this.config.RetryInterval) * time.Second)
	}

	return nil
}

func (this *SyncService) waitForNeoBlock() {
	response := this.neoSdk.GetBlockCount()
	currentNeoHeight := uint32(response.Result - 1)
	newNeoHeight := currentNeoHeight
	for currentNeoHeight == newNeoHeight {
		time.Sleep(time.Duration(15) * time.Second)
		newResponse := this.neoSdk.GetBlockCount()
		newNeoHeight = uint32(newResponse.Result - 1)
	}
}

func (this *SyncService) getCurrentPolyBookKeeps() error {
	scriptHash, err := helper.UInt160FromString(this.config.NeoConfig.CCMC) // hex string in little endian
	if err != nil {
		return fmt.Errorf("neo ccmc conversion error: %s", err)
	}
	script, err := sc.MakeScript(scriptHash, GET_BOOK_KEEPERS, []interface{}{})
	if err != nil {
		return fmt.Errorf("sc.MakeScript error: %s", err)
	}
	response := this.neoSdk.InvokeScript(crypto.Base64Encode(script), nil)
	if response.HasError() {
		return fmt.Errorf("InvokeScript error: %s", response.GetErrorInfo())
	}
	if len(response.Result.Stack) == 0 {
		return fmt.Errorf("InvokeScript response stack incorrect length")
	}
	stack0 := response.Result.Stack[0] // Array of ByteArray
	stack0.Convert()
	if stack0.Type != "Array" {
		return fmt.Errorf("InvokeScript response stack incorrect type")
	}
	values := stack0.Value.([]models.InvokeStack)

	pubKeys := make([][]byte, len(values))
	for i, v := range values {
		if v.Type != "ByteString" {
			return fmt.Errorf("InvokeScript response inside stack incorrect type")
		}
		s, err := crypto.Base64Decode(v.Value.(string))
		if err != nil {
			return fmt.Errorf("crypto.Base64Decode error: %s", err)
		}
		//pubKey, err := crypto.FromBytes(s, btcec.S256())
		pubKey, err := btcec.ParsePubKey(s, btcec.S256())
		if err != nil {
			return fmt.Errorf("crypto.NewECPointFromString error: %s", err)
		}
		pubKeys[i] = pubKey.SerializeUncompressed() // length 65
		//Log.Infof(helper.BytesToHex(pubKeys[i]))
	}
	this.polyPubKeys = pubKeys
	return nil
}

// sort signatures according to public key order, append sorted signatures together
func (this *SyncService) sortSignatures(sigs [][]byte, hash []byte) ([]byte, error) {
	// ----------------------------------------------------------------
	//// get pubKeys from db if nil
	//if len(this.polyPubKeys) == 0 {
	//	pubKeys, err := this.db.GetPPKS()
	//	if err != nil {
	//		return nil, err
	//	}
	//	if len(pubKeys) == 0 {
	//		return nil, fmt.Errorf("relay public keys not found in db")
	//	}
	//	if len(pubKeys)%65 != 0 {
	//		return nil, fmt.Errorf("wrong length for relay public keys in db")
	//	}
	//	this.polyPubKeys = recoverPublicKeys(pubKeys)
	//}
	// ------------------------------------------------------------------

	// get pubKeys from ccmc
	err := this.getCurrentPolyBookKeeps()
	if err != nil {
		return nil, fmt.Errorf("getCurrentPolyBookKeeps error: %s", err)
	}
	return sortSignatures(this.polyPubKeys, sigs, hash)
}

//func (this *SyncService) checkIsNeo2Wrapper(applicationLog models2.RpcApplicationLog) bool {
//	for _, execution := range applicationLog.Executions {
//		if execution.VMState == "FAULT" {
//			return false
//		}
//		notifications := execution.Notifications
//		for _, notification := range notifications {
//			u, _ := helper2.UInt160FromString(notification.Contract)
//			s := "0x" + u.String()
//			if s == this.config.Neo2Wrapper {
//				return true
//			}
//		}
//	}
//	return false
//}

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

const PolyPublicKeyLength int = 67

func recoverPublicKeys(pubKeys []byte) [][]byte {
	count := len(pubKeys) / PolyPublicKeyLength
	relayPubKeys := make([][]byte, count)
	for i := 0; i < count; i++ {
		relayPubKeys[i] = pubKeys[i*PolyPublicKeyLength : i*PolyPublicKeyLength+PolyPublicKeyLength]
	}
	return relayPubKeys
}

func getRelayUncompressedKey(key keypair.PublicKey) []byte {
	var buff bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		switch t.Algorithm {
		case ec.ECDSA:
			// Take P-256 as a special case
			if t.Params().Name == elliptic.P256().Params().Name {
				return ec.EncodePublicKey(t.PublicKey, false)
			}
			buff.WriteByte(byte(0x12))
		case ec.SM2:
			buff.WriteByte(byte(0x13))
		}
		label, err := getCurveLabel(t.Curve.Params().Name)
		if err != nil {
			panic(err)
		}
		buff.WriteByte(label)
		buff.Write(ec.EncodePublicKey(t.PublicKey, false))
	default:
		panic("err")
	}
	return buff.Bytes()
}

func getCurveLabel(name string) (byte, error) {
	switch strings.ToUpper(name) {
	case strings.ToUpper(elliptic.P224().Params().Name):
		return 1, nil
	case strings.ToUpper(elliptic.P256().Params().Name):
		return 2, nil
	case strings.ToUpper(elliptic.P384().Params().Name):
		return 3, nil
	case strings.ToUpper(elliptic.P521().Params().Name):
		return 4, nil
	case strings.ToUpper(sm2.SM2P256V1().Params().Name):
		return 20, nil
	case strings.ToUpper(btcec.S256().Name):
		return 5, nil
	default:
		panic("err")
	}
}

func recoverPublicKeyFromSignature(sig, hash []byte) ([]byte, error) {
	s, err := signature.Deserialize(sig)
	if err != nil {
		return nil, err
	}
	t, ok := s.Value.([]byte)
	if !ok {
		return nil, errors.New("invalid signature type")
	}
	if len(t) != 65 {
		return nil, errors.New("invalid signature length")
	}

	pubKey, _, err := btcec.RecoverCompact(btcec.S256(), t, hash) // S256 is secp256k1, P256 is secp256r1,
	if err != nil {
		return nil, err
	}
	return pubKey.SerializeUncompressed(), nil // length in 65
}

func recoverPublicKeyFromSignature1(sig, hash []byte) ([]byte, error) {
	s, err := signature.Deserialize(sig)
	if err != nil {
		return nil, err
	}
	t, ok := s.Value.([]byte)
	if !ok {
		return nil, errors.New("invalid signature type")
	}
	if len(t) != 65 {
		return nil, errors.New("invalid signature length")
	}

	pubKey, _, err := btcec.RecoverCompact(btcec.S256(), t, hash) // S256 is secp256k1, P256 is secp256r1,
	if err != nil {
		return nil, err
	}
	return pubKey.SerializeCompressed(), nil // length in 65
}

func appLogNotificationContains(notifications []models.RpcNotification, contract string, msg string) bool {
	if len(notifications) != 0 {
		for _, notif := range notifications {
			if contract != "" {
				if notif.Contract != contract {
					continue
				}
			}
			if notif.State.Type == "Array" {
				notif.State.Convert()
				results := notif.State.Value.([]models.InvokeStack)
				for _, result := range results {
					if result.Type == "ByteString" {
						s := result.Value.(string)
						bs, _ := crypto.Base64Decode(s)
						if string(bs) == msg {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
