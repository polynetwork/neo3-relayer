package service

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/ethereum/go-ethereum/contracts/native/go_abi/header_sync_abi"
	"github.com/joeqian10/neo3-gogogo/block"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/native/go_abi/cross_chain_manager_abi"
	hsCommon "github.com/ethereum/go-ethereum/contracts/native/header_sync/common"
	"github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/joeqian10/neo3-gogogo/crypto"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/joeqian10/neo3-gogogo/io"
	"github.com/joeqian10/neo3-gogogo/mpt"
	"github.com/joeqian10/neo3-gogogo/rpc/models"
)

const PUT = "PUT"
const PATCH = "PATCH"
const FLAMINGO = "flamingo"

func (this *SyncService) getCurrentNeoHeight() uint64 {
	errorRecorded := false
	for {
		response := this.neoSdk.GetBlockCount()
		if response.HasError() {
			if !errorRecorded {
				Log.Errorf("neoSdk.GetBlockCount error: %s, retrying...", response.GetErrorInfo())
				errorRecorded = true
			}
			time.Sleep(10 * time.Second)
			continue
		}
		errorRecorded = false
		if response.Result == 0 {
			if !errorRecorded {
				Log.Errorf("neoSdk.GetBlockCount response is empty, retrying...")
				errorRecorded = true
			}
			time.Sleep(10 * time.Second)
			continue
		}
		return uint64(response.Result - 1)
	}
}

func (this *SyncService) getNeoStartHeight() uint64 {
	startHeight := this.config.ForceConfig.NeoStartHeight
	if startHeight > 0 {
		return startHeight
	}
	startHeight = this.db.GetNeoHeight()
	if startHeight > 0 {
		return startHeight
	}
	return this.getCurrentNeoHeight()
}

func (this *SyncService) getNeoBlock(hashOrIndex string) models.RpcBlock {
	errorRecorded := false
	for {
		response := this.neoSdk.GetBlock(hashOrIndex)
		if response.HasError() {
			if !errorRecorded {
				Log.Errorf("neoSdk.GetBlock error: %s, retrying...", response.GetErrorInfo())
				errorRecorded = true
			}
			time.Sleep(10 * time.Second)
			continue
		}
		errorRecorded = false
		blk := response.Result
		if blk.Hash == EMPTY {
			if !errorRecorded {
				Log.Errorf("neoSdk.GetBlock response is empty, retrying...")
				errorRecorded = true
			}
			time.Sleep(10 * time.Second)
			continue
		}
		return blk
	}
}

// GetLatestSyncHeightOnZion - get the synced NEO blockHeight on zion
func (this *SyncService) GetLatestSyncHeightOnZion(neoChainID uint64) (uint64, error) {
	var id [8]byte
	binary.LittleEndian.PutUint64(id[:], neoChainID)
	heightBytes, err := this.zionSdk.GetStorage(utils.HeaderSyncContractAddress, append([]byte(hsCommon.CURRENT_HEADER_HEIGHT), id[:]...))
	if err != nil {
		return 0, fmt.Errorf("getStorage error: %s", err)
	}
	if heightBytes == nil {
		return 0, fmt.Errorf("get side chain height failed, height store is nil")
	}
	var height uint64
	if len(heightBytes) > 7 {
		height = binary.LittleEndian.Uint64(heightBytes)
	} else if len(heightBytes) > 3 {
		height = uint64(binary.LittleEndian.Uint32(heightBytes))
	} else {
		err = fmt.Errorf("Failed to decode heightBytes, %v", heightBytes)
	}
	height++ // means the next
	return height, nil
}

func (this *SyncService) processNeoTx(tx models.RpcTransaction, height uint64) error {
	response := this.neoSdk.GetApplicationLog(tx.Hash)
	if response.HasError() {
		//if strings.Contains(response.GetErrorInfo(), "Unknown transaction") {
		//	return
		//}
		return fmt.Errorf("neoSdk.GetApplicationLog error: %s", response.GetErrorInfo())
	}

	for _, execution := range response.Result.Executions {
		// skip fault transactions
		if execution.VMState == "FAULT" {
			continue
		}
		notifications := execution.Notifications
		// outer loop confirm tx is a cross chain tx
		for _, notification := range execution.Notifications {
			u, _ := helper.UInt160FromString(notification.Contract)
			if "0x"+u.String() == this.config.NeoConfig.CCMC && notification.EventName == "CrossChainLockEvent" { // big endian
				if notification.State.Type != "Array" {
					return fmt.Errorf("notification.State.Type error: Type is not Array")
				}
				notification.State.Convert() // convert Value to []InvokeStack
				states := notification.State.Value.([]models.InvokeStack)
				if len(states) != 5 { // CrossChainLockEvent(caller, para.fromContract, toChainID, resquestKey, para.args);
					return fmt.Errorf("notification.State.Value error: Wrong length of states")
				}
				// when empty, relay everything
				if this.config.CustomConfig.N2ZContract != EMPTY {
					// this loop check it is for this specific contract
					for index, ntf := range notifications {
						if ntf.Contract != this.config.CustomConfig.N2ZContract { // wrapper contract, big endian
							if index < len(notifications)-1 {
								continue
							}
							Log.Infof("[neoToRelay] this tx %s does not call the expected contract", tx.Hash)
							goto NEXT
						} else {
							break
						}
						//ntf.State.Convert()
						//states2 := ntf.State.Value.([]models.InvokeStack)
						//if len(states2) != 6 { // LockEvent(fromAssetHash, fromAddress, toChainId, toAddress, amount, index);
						//	continue
						//}
					}
				}
				// get key
				key := states[3].Value.(string)       // base64 string for storeKey: 0102 + toChainId + toRequestId, like 01020501
				temp, err := crypto.Base64Decode(key) // base64 encoded
				if err != nil {
					return fmt.Errorf("crypto.Base64Decode key error: %s", err)
				}
				key = helper.BytesToHex(temp)
				// get the neo chain synced height on zion
				latestSyncHeight, err := this.GetLatestSyncHeightOnZion(this.config.NeoConfig.SideChainId)
				if err != nil {
					return fmt.Errorf("GetCurrentMainChainSyncHeight error: %s", err)
				}
				var usedHeight uint64
				if height >= latestSyncHeight {
					usedHeight = height
				} else {
					usedHeight = latestSyncHeight
				}

				Log.Infof("process neo tx: %s", tx.Hash)
				err = this.syncProofToZion(key, usedHeight, tx.Hash)
				if err != nil {
					return fmt.Errorf("syncProofToZion error: %s", err)
				}
			}
		NEXT:
		} // notification
	} // execution
	return nil
}

// syncProofToRelay
func (this *SyncService) syncProofToZion(key string, height uint64, neoHash string) error {
	//get current state height
	var stateHeight uint64 = 0
	for stateHeight < height {
		res := this.neoSdk.GetStateHeight()
		if res.HasError() {
			return fmt.Errorf("neoSdk.GetStateHeight error: %s", res.GetErrorInfo())
		}
		stateHeight = uint64(res.Result.ValidateRootIndex)
	}

	// get state root
	srGot := false
	var height2 uint64
	stateRoot := mpt.StateRoot{}
	if height >= this.neoStateRootHeight {
		height2 = height
	} else {
		height2 = this.neoStateRootHeight
	}
	for !srGot {
		res2 := this.neoSdk.GetStateRoot(uint32(height2))
		if res2.HasError() {
			return fmt.Errorf("neoSdk.GetStateRootByIndex error: %s", res2.GetErrorInfo())
		}
		stateRoot = res2.Result
		if len(stateRoot.Witnesses) == 0 { // no witness
			height2++
		} else {
			srGot = true
			this.neoStateRootHeight = height2 // next tx can start from this height to get state root
		}
	}
	buff := io.NewBufBinaryWriter()
	stateRoot.Serialize(buff.BinaryWriter)
	crossChainMsg := buff.Bytes()
	//Log.Infof("stateroot: %s", helper.BytesToHex(crossChainMsg))

	// get proof
	res3 := this.neoSdk.GetProof(stateRoot.RootHash, this.config.NeoConfig.CCMC, crypto.Base64Encode(helper.HexToBytes(key)))
	if res3.HasError() {
		return fmt.Errorf("neoSdk.GetProof error: %s", res3.Error.Message)
	}
	proof, err := crypto.Base64Decode(res3.Result)
	if err != nil {
		return fmt.Errorf("decode proof error: %s", err)
	}
	//Log.Info("proof: %s", helper.BytesToHex(proof))

	id, k, proofs, err := mpt.ResolveProof(proof)
	if err != nil {
		return fmt.Errorf("ResolveProof error: %s", err)
	}
	root, _ := helper.UInt256FromString(stateRoot.RootHash)
	value, err := mpt.VerifyProof(root, id, k, proofs)
	if err != nil {
		return fmt.Errorf("VerifyProof error: %s", err)
	}
	cctp, err := DeserializeCrossChainTxParameter(value)
	if err != nil {
		return fmt.Errorf("DeserializeCrossChainTxParameter error: %s", err)
	}
	//Log.Infof("value: %s", helper.BytesToHex(value))

	// sending SyncProof transaction to zion
	zionHash, err := this.makeZionTx(utils.CrossChainManagerContractAddress,
		cross_chain_manager_abi.CrossChainManagerABI,
		IMPORT_OUTER_TRANSFER,
		this.config.NeoConfig.SideChainId,
		height,
		proof,
		this.zionSigner.Address[:],
		crossChainMsg) // todo, arg positions may be changed
	if err != nil {
		if strings.Contains(err.Error(), "tx already done") {
			Log.Infof("[syncProofToZion] tx already imported, source tx hash: %s", helper.BytesToHex(cctp.TxHash))
			return nil
		} else {
			return fmt.Errorf("makeZionTx error: %v, height: %d, crossChainMsg: %s, proof: %s",
				err, height, helper.BytesToHex(crossChainMsg), helper.BytesToHex(proof))
		}
	}
	err = this.waitZionTx(zionHash)
	if err != nil {
		Log.Errorf("[syncProofToZion] waitZionTx error: %v, zionTxHash: %s", err, zionHash)
		return err
	}
	Log.Infof("[syncProofToZion] neo tx: %s processed, zion tx: %s", neoHash, zionHash)
	return nil
}

func (this *SyncService) syncHeaderToZion(blk models.RpcBlock) error {
	blockHeader, err := block.NewBlockHeaderFromRPC(&blk.RpcBlockHeader)
	if err != nil {
		return fmt.Errorf("block.NewBlockHeaderFromRPC error: %s", err)
	}

	buff := io.NewBufBinaryWriter()
	blockHeader.Serialize(buff.BinaryWriter)
	header := buff.Bytes()

	txHash, err := this.makeZionTx(utils.HeaderSyncContractAddress,
		header_sync_abi.HeaderSyncABI,
		SYNC_BLOCK_HEADER,
		this.config.NeoConfig.SideChainId,
		this.zionSigner.Address,
		[][]byte{header}) // todo, arg positions may be changed
	if err != nil {
		return fmt.Errorf("makeZionTx error: %v", err)
	}
	err = this.waitZionTx(txHash)
	if err != nil {
		Log.Errorf("[syncHeaderToZion] waitZionTx error: %v, zionTxHash: %s", err, txHash)
		return err
	}
	Log.Infof("[syncHeaderToZion] tx done, zionTxHash: %v", txHash)
	return nil
}

func (this *SyncService) makeZionTx(contractAddress common.Address, contractAbi string, method string, args ...interface{}) (string, error) {
	timerCtx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFunc()

	ethCli := this.zionSdk.GetEthClient()
	gasPrice, err := ethCli.SuggestGasPrice(timerCtx)
	if err != nil {
		return EMPTY, fmt.Errorf("SuggestGasPrice error: %v", err)
	}
	conAbi, err := abi.JSON(strings.NewReader(contractAbi))
	if err != nil {
		return EMPTY, fmt.Errorf("abi.JSON CrossChainManagerABI error: %v", err)
	}
	data, err := conAbi.Pack(method, args)
	if err != nil {
		return EMPTY, fmt.Errorf("pack zion tx data error: %v", err)
	}
	callMsg := ethereum.CallMsg{
		From:     this.zionSigner.Address,
		To:       &contractAddress,
		Gas:      0,
		GasPrice: gasPrice,
		Value:    big.NewInt(0),
		Data:     data,
	}
	gasLimit, err := ethCli.EstimateGas(timerCtx, callMsg)
	if err != nil {
		return EMPTY, fmt.Errorf("EstimateGas error: %v", err)
	}

	nonce, err := ethCli.NonceAt(context.Background(), this.zionSigner.Address, nil)
	if err != nil {
		return EMPTY, fmt.Errorf("NonceAt error: %v", err)
	}
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gasLimit,
		To:       &contractAddress,
		Value:    big.NewInt(0),
		Data:     data,
	})
	s := types.LatestSignerForChainID(this.zionChainId)

	signedTx, err := types.SignTx(tx, s, this.zionSigner.PrivateKey)
	if err != nil {
		return EMPTY, fmt.Errorf("SignTx error: %v", err)
	}
	err = ethCli.SendTransaction(timerCtx, signedTx)
	if err != nil {
		return EMPTY, fmt.Errorf("SendTransaction error: %v", err)
	}

	zionHash := signedTx.Hash().Hex()
	return zionHash, nil
}

func (this *SyncService) waitZionTx(txHash string) error {
	start := time.Now()
	for {
		duration := time.Second * 30
		timerCtx, cancelFunc := context.WithTimeout(context.Background(), duration)
		receipt, err := this.zionSdk.GetEthClient().TransactionReceipt(timerCtx, common.HexToHash(txHash))
		cancelFunc()
		if receipt == nil || err != nil {
			if time.Since(start) > time.Minute*5 {
				err = fmt.Errorf("waitTx timeout")
				return err
			}
			time.Sleep(time.Second)
			continue
		}
		return nil
	}
}
