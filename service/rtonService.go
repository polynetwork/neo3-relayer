package service

import (
	"encoding/json"
	"fmt"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	"github.com/polynetwork/poly/native/service/utils"
	"time"
)

// RelayToNeo sync headers from relay chain to neo
func (this *SyncService) RelayToNeo() {
	this.polyStartHeight = this.config.ForceConfig.PolyStartHeight
	for {
		currentRelayChainHeight, err := this.polySdk.GetCurrentBlockHeight()
		if err != nil {
			Log.Errorf("[RelayToNeo] GetCurrentBlockHeight error: ", err)
		}
		err = this.relayToNeo(this.polyStartHeight, currentRelayChainHeight)
		if err != nil {
			Log.Errorf("[RelayToNeo] relayToNeo error: ", err)
		}
		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second)
	}
}

func (this *SyncService) relayToNeo(m, n uint32) error {
	for i := m; i < n; i++ {
		Log.Infof("start parse block %d", i)

		block, err := this.polySdk.GetBlockByHeight(i)
		if err != nil {
			return fmt.Errorf("GetBlockByHeight error: %s", err)
		}
		txs := block.Transactions
		for _, tx := range txs {
			txHash := tx.Hash()
			event, err := this.polySdk.GetSmartContractEvent(txHash.ToHexString())
			if err != nil {
				return fmt.Errorf("polySdk.GetSmartContractEvent error: %s, tx: %s", err, txHash.ToHexString())
			}
			for _, notify := range event.Notify {
				states, ok := notify.States.([]interface{})
				if !ok {
					continue
				}
				// todo, SignatureManagerContractAddress
				if notify.ContractAddress !=  utils.SignatureManagerContractAddress.ToHexString() {
					continue
				}
				// States: []interface{}{"AddSignatureQuorum", id, params.Subject, params.SideChainID},
				name := states[0].(string)
				if name == "AddSignatureQuorum" {
					toChainID := uint64(states[3].(float64))
					if toChainID == this.config.NeoConfig.SideChainID {
						id := states[1].([]byte)
						subject := states[2].([]byte)
						if len(tx.Sigs) <= 0 {
							return fmt.Errorf("tx: %s has no sigs", txHash.ToHexString())
						}
						sigData := tx.Sigs[0].SigData
						err = this.syncProofToNeo(i, id, subject, sigData)
						if err != nil {
							Log.Errorf("--------------------------------------------------")
							Log.Errorf("syncProofToNeo error: %s", err)
							Log.Errorf("polyHeight: %d, hash: %s", i, txHash.ToHexString())
							Log.Errorf("--------------------------------------------------")
						}
					}
				}
			}
		}

		if this.config.PolyConfig.ChangeBookkeeper {
			// sync key header, change book keeper,
			// but should be done after all cross chain tx in this block are handled for verification purpose.
			blkInfo := &vconfig.VbftBlockInfo{}
			if err := json.Unmarshal(block.Header.ConsensusPayload, blkInfo); err != nil {
				return fmt.Errorf("[relayToNeo] unmarshal blockInfo error: %s", err)
			}
			if blkInfo.NewChainConfig != nil {
				this.waitForNeoBlock() // wait for neo block
				err = this.changeBookKeeper(block)
				if err != nil {
					Log.Errorf("--------------------------------------------------")
					Log.Errorf("[relayToNeo] syncHeaderToNeo error: %s", err)
					Log.Errorf("polyHeight: %d", i)
					Log.Errorf("--------------------------------------------------")
				}
			}
		}

		this.polyStartHeight++
	}
	return nil
}

func (this *SyncService) RelayToNeoCheckAndRetry() {
	for {
		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second) // 15 seconds a block
		err := this.neoCheckTx()
		if err != nil {
			Log.Errorf("[RelayToNeoCheckAndRetry] this.neoCheckTx error: %s", err)
		}
		err = this.neoRetryTx()
		if err != nil {
			Log.Errorf("[RelayToNeoCheckAndRetry] this.neoRetryTx error: %s", err)
		}
	}
}
