package service

import (
	"bytes"
	"context"
	goc "crypto"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	common2 "github.com/ethereum/go-ethereum/contracts/native/cross_chain_manager/common"
	"github.com/ethereum/go-ethereum/contracts/native/governance/node_manager"
	"github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	crypto3 "github.com/joeqian10/neo3-gogogo/crypto"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/joeqian10/neo3-gogogo/rpc/models"
	"github.com/joeqian10/neo3-gogogo/sc"
	"github.com/joeqian10/neo3-gogogo/tx"

	"github.com/polynetwork/neo3-relayer/db"
)

const (
	VERIFY_AND_EXECUTE_TX = "verifyAndExecuteTx"
	CHANGE_BOOK_KEEPER    = "changeEpoch"
	GET_BOOK_KEEPERS      = "getBookKeepers"
)

// getCurrentNeoChainSyncHeight gets the synced Zion height from Neo CCMC storage
func (this *SyncService) getCurrentNeoChainSyncHeight() (uint64, error) {
	response := this.neoSdk.GetStorage(this.config.NeoConfig.CCMC, "AgE=")
	if response.HasError() {
		return 0, fmt.Errorf("[getCurrentNeoChainSyncHeight] GetStorage error: %s", response.GetErrorInfo())
	}
	var height uint64
	s := response.Result
	if s == "" {
		return 0, nil
	}
	b, err := crypto3.Base64Decode(s)
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

// changeEpoch inside needs four parameters: rawHeader, rawHeaderHash, newPubKeyList, signList []byte
func (this *SyncService) changeEpoch(header *types.Header) error {
	extra, err := types.ExtractHotstuffExtra(header)
	if len(extra.Validators) == 0 { // not key header
		return nil
	}
	// wait for neo block in case of a cross chain tx in the same block
	this.waitForNeoBlock()
	// raw header
	rawHeaderBytes, err := rlp.EncodeToBytes(types.HotstuffFilteredHeader(header, false))
	if err != nil {
		return fmt.Errorf("header rlp.EncodeToBytes error: %s", err)
	}
	cp1 := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: rawHeaderBytes,
	}
	Log.Infof("raw header: %s", helper.BytesToHex(rawHeaderBytes))

	// header hash
	hashBytes := header.Hash().Bytes()
	cp2 := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: hashBytes,
	}
	Log.Infof("header hash: %s", helper.BytesToHex(hashBytes))

	// public keys
	// get current epoch, epoch.StartHeight must >= header.height
	bs, err := this.getChangingZionValidators(header.Number.Uint64())
	if err != nil {
		return fmt.Errorf("getChangingZionValidators error: %s", err)
	}
	cp3 := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: bs,
	}

	// signatures
	var ss []byte
	if len(extra.CommittedSeal) == 0 {
		ss = []byte{}
	} else {
		ss, err = this.sortSignatures(extra.CommittedSeal, hashBytes)
		if err != nil {
			return fmt.Errorf("[changeBookKeeper] sort signatures error: %s", err)
		}
	}
	cp4 := sc.ContractParameter{
		Type:  sc.ByteArray,
		Value: ss,
	}
	Log.Infof("signature: %s", helper.BytesToHex(ss))

	// build script
	scriptHash, err := helper.UInt160FromString(this.config.NeoConfig.CCMC) // "0x" prefixed hex string in big endian
	if err != nil {
		return fmt.Errorf("[changeBookKeeper] neo ccmc conversion error: %s", err)
	}
	script, err := sc.MakeScript(scriptHash, CHANGE_BOOK_KEEPER, []interface{}{cp1, cp2, cp3, cp4})
	if err != nil {
		return fmt.Errorf("[changeBookKeeper] sc.MakeScript error: %s", err)
	}

	Log.Infof("script: " + crypto3.Base64Encode(script))

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
	rawTxString := crypto3.Base64Encode(trx.ToByteArray())
	Log.Infof(rawTxString)

	// send the raw transaction
	response := this.neoSdk.SendRawTransaction(rawTxString)
	if response.HasError() {
		return fmt.Errorf("SendRawTransaction error: %s, "+
			"raw header: %s, "+
			"header hash: %s, "+
			"public keys: %s, "+
			"signatures: %s, "+
			"script: %s, "+
			"changeBookKeeper RawTransactionString: %s",
			response.ErrorResponse.Error.Message,
			helper.BytesToHex(rawHeaderBytes),
			helper.BytesToHex(hashBytes),
			helper.BytesToHex(bs),
			helper.BytesToHex(ss),
			helper.BytesToHex(script),
			rawTxString)
	}

	Log.Infof("[changeBookKeeper] txHash is: %s", trx.GetHash().String())

	return nil
}

func (this *SyncService) syncProofToNeo(height uint64, id []byte, subject []byte, sigData [][]byte) error {
	// rlp.Decode
	toMerkleValue := new(common2.ToMerkleValue)
	r:= bytes.NewReader(subject)
	stream := rlp.NewStream(r, uint64(len(subject)))
	err := toMerkleValue.DecodeRLP(stream)

	zionHash := helper.BytesToHex(toMerkleValue.TxHash)

	// check if it is zion to neo contract
	if this.config.CustomConfig.Z2NContract != "" {
		got := "0x" + helper.BytesToHex(helper.ReverseBytes(toMerkleValue.MakeTxParam.ToContractAddress)) // little endian
		expected := this.config.CustomConfig.Z2NContract                                       // big endian
		if got != expected {
			Log.Infof("this tx is not from the expected contract, expected contract: %s, but got: %s", expected, got)
			return nil
		}
	}

	if this.IsAllowedMethod(toMerkleValue.MakeTxParam.Method) {
		return fmt.Errorf("called method %s is invalid", toMerkleValue.MakeTxParam.Method)
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

	balancesGas, err := this.nwh.GetAccountAndBalance(tx.GasToken)
	if err != nil {
		return fmt.Errorf("WalletHelper.GetAccountAndBalance error: %s", err)
	}

	record := &db.Record{
		Height:  height,
		TxHash:  zionHash,
		Id:      id,
		Subject: subject,
	}
	sink := common.NewZeroCopySink(nil)
	record.Serialization(sink)
	v := sink.Bytes()

	neoTrx, err := this.nwh.MakeTransaction(script, nil, []tx.ITransactionAttribute{}, balancesGas)
	if err != nil {
		return fmt.Errorf("WalletHelper.MakeTransaction error: %s", err)
	}

	// sign transaction
	neoTrx, err = this.nwh.SignTransaction(neoTrx, this.config.NeoConfig.NeoMagic)
	if err != nil {
		return fmt.Errorf("WalletHelper.SignTransaction error: %s", err)
	}
	rawTxString := crypto3.Base64Encode(neoTrx.ToByteArray())

	// send the raw transaction
	response := this.neoSdk.SendRawTransaction(rawTxString)
	if response.HasError() {
		return fmt.Errorf("SendRawTransaction error: %s, "+
			"height: %d, "+
			"id: %s, " +
			"cross chain info: %s, " +
			"signatures: %s, " +
			"script hex string: %s, "+
			"raw tx string: %s",
			response.GetErrorInfo(),
			height,
			helper.BytesToHex(id),
			helper.BytesToHex(subject),
			helper.BytesToHex(signListBytes),
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

func (this *SyncService) neoCheckTx() error {
	checkMap, err := this.db.GetNeoAllCheck()
	if err != nil {
		return fmt.Errorf("this.db.GetNeoAllCheck error: %s", err)
	}
	for k, v := range checkMap {
		record := new(db.Record)
		err := record.Deserialization(common.NewZeroCopySource(v))
		if err != nil {
			return fmt.Errorf("record.Deserialization error: %s", err)
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
			Log.Errorf("tx engine faulted, neoHash: %s, zionHash: %s at height %d, exception: %s", k, record.TxHash, record.Height, exec.Exception)
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
					Log.Errorf("tx stack result is false, neoHash: %s, zionHash: %s at height %d, check app log details and record", k, record.TxHash, record.Height)
				}
				continue
			}
		}
		Log.Infof("tx is successful, hash: %s, zionHash: %s at height %d", k, record.TxHash, record.Height)
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

func (this *SyncService) getChangingZionValidators(height uint64) ([]byte, error) {
	node_manager.InitABI()
	input := new(node_manager.MethodEpochInput)

	payload, err := input.Encode()
	if err != nil {
		return nil, fmt.Errorf("MethodGetEpochInput.Encode error: %s", err.Error())
	}
	arg := ethereum.CallMsg{
		From: common.Address{},
		To:   &utils.NodeManagerContractAddress,
		Data: payload,
	}
	res, err := this.zionSdk.GetEthClient().CallContract(context.Background(), arg, nil)
	if err != nil {
		return nil, fmt.Errorf("EthClient.CallContract error: %s", err.Error())
	}
	output := new(node_manager.MethodEpochOutput)
	if err = output.Decode(res); err != nil {
		return nil, fmt.Errorf("MethodEpochOutput error: %s", err.Error())
	}
	epochInfo := output.Epoch
	if epochInfo.StartHeight < height {
		return nil, fmt.Errorf("changing epoch means current Zion epoch height %d must be no less than height %d", epochInfo.StartHeight, height)
	}
	peers := epochInfo.Peers.List
	// sort public keys
	pubKeyList := []*ecdsa.PublicKey{}
	for _, peer := range peers {
		s := strings.TrimPrefix(peer.PubKey, "0x")
		keyBytes, _ := hex.DecodeString(s)
		pubKey, _ := crypto.DecompressPubkey(keyBytes)
		pubKeyList = append(pubKeyList, pubKey)
	}
	bs := []byte{}
	pubKeyList = sortPublicKeys(pubKeyList)
	for _, pubKey := range pubKeyList {
		keyBytes := crypto.CompressPubkey(pubKey)
		bs = append(bs, keyBytes...)
	}
	return bs, nil
}

func (this *SyncService) getZionValidatorsFromNeo() error {
	scriptHash, err := helper.UInt160FromString(this.config.NeoConfig.CCMC) // hex string in little endian
	if err != nil {
		return fmt.Errorf("neo ccmc conversion error: %s", err)
	}
	script, err := sc.MakeScript(scriptHash, GET_BOOK_KEEPERS, []interface{}{})
	if err != nil {
		return fmt.Errorf("sc.MakeScript error: %s", err)
	}
	response := this.neoSdk.InvokeScript(crypto3.Base64Encode(script), nil)
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
		s, err := crypto3.Base64Decode(v.Value.(string))
		if err != nil {
			return fmt.Errorf("crypto.Base64Decode error: %s", err)
		}
		//pubKey, err := crypto.FromBytes(s, btcec.S256())
		pubKey, err := btcec.ParsePubKey(s, btcec.S256())
		if err != nil {
			return fmt.Errorf("crypto.NewECPointFromString error: %s", err)
		}
		pubKeys[i] = pubKey.SerializeCompressed() // length 33
		//Log.Infof(helper.BytesToHex(pubKeys[i]))
	}
	this.zionPubKeys = pubKeys
	return nil
}

// sort signatures according to public key order, append sorted signatures together
func (this *SyncService) sortSignatures(sigs [][]byte, hash []byte) ([]byte, error) {
	// get pubKeys from ccmc
	err := this.getZionValidatorsFromNeo()
	if err != nil {
		return nil, fmt.Errorf("getCurrentPolyBookKeeps error: %s", err)
	}
	return sortSignatures(this.zionPubKeys, sigs, hash)
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
						bs, _ := crypto3.Base64Decode(s)
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
