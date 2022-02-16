package service

import (
	"fmt"
	"github.com/joeqian10/neo3-gogogo/crypto"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/joeqian10/neo3-gogogo/rpc/models"
	"strconv"
	"time"
)

//NeoToRelay ...
func (this *SyncService) NeoToRelay() {
	//this.relaySyncHeight, _ = this.GetCurrentRelayChainSyncHeight(this.config.NeoChainID)
	this.relaySyncHeight = this.config.NeoStartHeight // means the next height to be synced
	if this.relaySyncHeight == 0 {                    // means no block header has been synced
		this.neoNextConsensus = ""
	} else {
		for j := 0; j < 5; j++ { // 5 times rpc
			response := this.neoSdk.GetBlock(strconv.Itoa(int(this.relaySyncHeight - 1))) // get the last synced block
			if response.HasError() {
				Log.Errorf("[NeoToRelay] neoSdk.GetBlockByIndex error: %s", response.Error.Message)
			}
			block := response.Result
			if block.Hash == "" {
				if j == 4 {
					Log.Errorf("[NeoToRelay] rpc request failed 5 times")
					break
				}
				continue
			}
			this.neoNextConsensus = block.NextConsensus // set the next consensus to the last synced block
			break
		}
	}
	for {
		//get current Neo BlockHeight, 5 times rpc
		var currentNeoHeight uint32
		for j := 0; j < 5; j++ {
			response := this.neoSdk.GetBlockCount()
			if response.HasError() {
				Log.Errorf("[NeoToRelay] neoSdk.GetBlockCount error: ", response.Error.Message)
				break
			}
			if response.Result == 0 {
				if j == 4 {
					Log.Errorf("[NeoToRelay] rpc request failed 5 times")
					currentNeoHeight = this.relaySyncHeight // prevent infinite loop
					break
				}
				continue
			}
			currentNeoHeight = uint32(response.Result - 1)
			break
		}
		err := this.neoToRelay(this.relaySyncHeight, currentNeoHeight)
		if err != nil {
			Log.Errorf("[NeoToRelay] neoToRelay error:", err)
		}
		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second)
	}
}

func (this *SyncService) neoToRelay(m, n uint32) error {
	for i := m; i < n; i++ {
		Log.Infof("[neoToRelay] start processing NEO block %d", this.relaySyncHeight)
		// request block from NEO, try rpc request 5 times, if failed, continue
		for j := 0; j < 5; j++ {
			blockResponse := this.neoSdk.GetBlock(strconv.Itoa(int(i)))
			if blockResponse.HasError() {
				return fmt.Errorf("[neoToRelay] neoSdk.GetBlockByIndex error: %s", blockResponse.GetErrorInfo())
			}
			blk := blockResponse.Result
			if blk.Hash == "" {
				if j == 4 {
					Log.Errorf("[neoToRelay] rpc request failed 5 times")
					break
				}
				continue
			}

			// sync cross chain transaction
			// check if this block contains cross chain tx
			txs := blk.Tx
			for _, tx := range txs {
				// check tx script is useless since which contract calling ccmc is not sure
				response := this.neoSdk.GetApplicationLog(tx.Hash)
				if response.HasError() {
					return fmt.Errorf("[neoToRelay] neoSdk.GetApplicationLog error: %s", response.GetErrorInfo())
				}

				for _, execution := range response.Result.Executions {
					if execution.VMState == "FAULT" { // skip fault transactions
						continue
					}
					notifications := execution.Notifications
					// this loop confirm tx is a cross chain tx
					for _, notification := range execution.Notifications {
						u, _ := helper.UInt160FromString(notification.Contract)
						if "0x"+u.String() == this.config.NeoCCMC && notification.EventName == "CrossChainLockEvent" {
							if notification.State.Type != "Array" {
								return fmt.Errorf("[neoToRelay] notification.State.Type error: Type is not Array")
							}
							notification.State.Convert() // Type == "Array"
							// convert to []InvokeStack
							states := notification.State.Value.([]models.InvokeStack)
							if len(states) != 5 {
								return fmt.Errorf("[neoToRelay] notification.State.Value error: Wrong length of states")
							}
							// when empty, relay everything
							if this.config.NtorContract != "" {
								// this loop check it is for this specific contract
								for index, ntf := range notifications {
									v, _ := helper.UInt160FromString(ntf.Contract)
									if "0x"+v.String() != this.config.NtorContract {
										if index < len(notifications)-1 {
											continue
										}
										Log.Infof("This cross chain tx is not for this specific contract.")
										goto NEXT
									} else {
										break
									}
								}
							}
							key := states[3].Value.(string)       // base64 string for storeKey: 0102 + toChainId + toRequestId, like 01020501
							temp, err := crypto.Base64Decode(key) // base64 encoded
							if err != nil {
								return fmt.Errorf("[neoToRelay] base64decode key error: %s", err)
							}
							key = helper.BytesToHex(temp)
							//get relay chain sync height
							currentRelayChainSyncHeight, err := this.GetCurrentRelayChainSyncHeight(this.config.NeoChainID)
							if err != nil {
								return fmt.Errorf("[neoToRelay] GetCurrentRelayChainSyncHeight error: %s", err)
							}
							var passed uint32
							if i >= currentRelayChainSyncHeight {
								passed = i
							} else {
								passed = currentRelayChainSyncHeight
							}
							Log.Infof("now process neo tx: " + tx.Hash)
							err = this.syncProofToRelay(key, passed)
							if err != nil {
								Log.Errorf("--------------------------------------------------")
								Log.Errorf("[neoToRelay] syncProofToRelay error: %s", err)
								Log.Errorf("neoHeight: %d, neoTxId: %s", i, tx.Hash)
								Log.Errorf("--------------------------------------------------")
							}
						}
					NEXT:
					} // notification
				} // execution
			}

			// if block.nextConsensus is changed, sync key header of NEO,
			// but should be done after all cross chain tx in this block are handled for verification purpose.
			if blk.NextConsensus != this.neoNextConsensus {
				Log.Infof("[neoToRelay] Syncing Key blockHeader from NEO: %d", blk.Index)
				// Syncing key blockHeader to Relay Chain
				err := this.syncHeaderToRelay(this.relaySyncHeight)
				if err != nil {
					Log.Errorf("--------------------------------------------------")
					Log.Errorf("[neoToRelay] syncHeaderToRelay error: %s", err)
					Log.Errorf("height: %d", i)
					Log.Errorf("--------------------------------------------------")
				}
				this.neoNextConsensus = blk.NextConsensus
			}

			this.relaySyncHeight++
			break
		}
	}
	return nil
}

func (this *SyncService) NeoToRelayCheckAndRetry() {
	for {
		err := this.checkDoneTx()
		if err != nil {
			Log.Errorf("[NeoToRelayCheckAndRetry] this.checkDoneTx error:%s", err)
		}
		err = this.retryTx()
		if err != nil {
			Log.Errorf("[NeoToRelayCheckAndRetry] this.retryTx error:%s", err)
		}
		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second)
	}
}
