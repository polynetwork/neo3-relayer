package service

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/contracts/native/go_abi/signature_manager_abi"
	"github.com/ethereum/go-ethereum/contracts/native/governance/signature_manager"
	"github.com/joeqian10/neo3-gogogo/helper"

	"github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/ethereum/go-ethereum/rlp"

	"time"
)

// ZionToNeo syncs from zion to neo
func (this *SyncService) ZionToNeo() {
	this.zionStartHeight = this.config.ForceConfig.ZionStartHeight
	for {
		currentZionHeight, err := this.zionSdk.GetNodeHeight()
		if err != nil {
			Log.Errorf("[ZionToNeo] GetCurrentBlockHeight error: ", err)
		}
		err = this.zionToNeo(this.zionStartHeight, currentZionHeight)
		if err != nil {
			Log.Errorf("[ZionToNeo] zionToNeo error: ", err)
		}
		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second)
	}
}

func (this *SyncService) zionToNeo(m, n uint64) error {
	for i := m; i < n; i++ {
		Log.Infof("start parse block %d", i)

		//----------if use NewCrossChainManager
		//ccm, err := cross_chain_manager_abi.NewCrossChainManager(utils.CrossChainManagerContractAddress, this.zionSdk.GetEthClient())
		//if err != nil {
		//	return fmt.Errorf("NewCrossChainManager error: %s", err)
		//}
		//opt := &bind.FilterOpts{
		//	Start:   i,
		//	End:     &i,
		//	Context: context.Background(),
		//}
		//events, err := ccm.FilterMakeProof(opt)
		//if err != nil {
		//	return fmt.Errorf("FilterMakeProof error: %s", err)
		//}
		//--------------

		sm, err := signature_manager_abi.NewSignatureManager(utils.SignatureManagerContractAddress, this.zionSdk.GetEthClient())
		if err != nil {
			return fmt.Errorf("NewSignatureManager error: %s", err)
		}
		opt := &bind.FilterOpts{
			Start:   i,
			End:     &i,
			Context: context.Background(),
		}
		// if the event is emitted, all the sigs are collected, and the status is true now
		events, err := sm.FilterAddSignatureQuorumEvent(opt)
		if err != nil {
			return fmt.Errorf("sm.FilterAddSignatureQuorumEvent error: %s", err)
		}
		if events != nil {
			for events.Next() {
				evt := events.Event
				// States: []interface{}{"AddSignatureQuorum", id, params.Subject, params.SideChainID},
				// AddNotify(ABI, []string{signature_manager_abi.EventAddSignatureQuorumEvent}, id, params.Subject, params.SideChainID)
				if evt.SideChainI.Uint64() != this.config.NeoConfig.SideChainID {
					continue
				}
				id := evt.Id
				subject := evt.Subject
				sigData, err := this.zionSdk.GetStorage(utils.SignatureManagerContractAddress, append([]byte(signature_manager.SIG_INFO), id[:]...))
				if err != nil {
					return fmt.Errorf("zion.GetStorage error: %v for id: %s at height: %d", err, helper.BytesToHex(id), i)
				}
				if len(sigData) == 0 {
					return fmt.Errorf("id: %s has no sigs at height: %d", helper.BytesToHex(id), i)
				}
				sigInfo := &signature_manager.SigInfo{}
				err = rlp.DecodeBytes(sigData, sigInfo)
				if err != nil {
					return fmt.Errorf("rlp.DecodeBytes error: %v for id: %s at height: %d", err, helper.BytesToHex(id), i)
				}
				if !sigInfo.Status {
					return fmt.Errorf("SigInfo.Status is not true for id: %s at height: %d", helper.BytesToHex(id), i)
				}
				ss := [][]byte{}
				for _, s := range sigInfo.SigInfo {
					ss = append(ss, s.Content)
				}
				err = this.syncProofToNeo(i, id, subject, ss)
				if err != nil {
					Log.Errorf("--------------------------------------------------")
					Log.Errorf("syncProofToNeo error: %v, for id: %s at height: %d", err, helper.BytesToHex(id), i)
					Log.Errorf("--------------------------------------------------")
				}

			}
		}

		//head, err := this.zionSdk.GetEthClient().HeaderByNumber(context.Background(), big.NewInt(int64(i)))
		//if err != nil {
		//	return fmt.Errorf("ethClient.HeaderByNumber error: %s", err)
		//}

		if this.config.ZionConfig.ChangeEpoch {
			// sync key header, change epoch,
			// but should be done after all cross chain tx in this block are handled for verification purpose.
			header, err := this.zionSdk.GetBlockHeader(i)
			if err != nil {
				return fmt.Errorf("GetBlockHeader error: %s", err)
			}

			err = this.changeEpoch(header)
			if err != nil {
				Log.Errorf("--------------------------------------------------")
				Log.Errorf("changeEpoch error: %s at zion height: %d", err, i)
				Log.Errorf("--------------------------------------------------")
			}
		}

		this.zionStartHeight++
	}
	return nil
}

func (this *SyncService) ZionToNeoCheck() {
	for {
		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second) // 15 seconds a block
		err := this.neoCheckTx()
		if err != nil {
			Log.Errorf("[ZionToNeoCheck] neoCheckTx error: %s", err)
		}
	}
}
