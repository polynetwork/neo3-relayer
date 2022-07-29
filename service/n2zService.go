package service

import (
	"fmt"
	"strconv"
	"time"
)

const (
	SYNC_BLOCK_HEADER     = "syncBlockHeader"
	IMPORT_OUTER_TRANSFER = "importOuterTransfer"
	EMPTY                 = ""
)

// NeoToZion ...
func (this *SyncService) NeoToZion() {
	this.neoStartHeight = this.getNeoStartHeight() // means the next neo height to be synced
	if this.neoStartHeight == 0 {
		this.neoNextConsensus = EMPTY
	} else {
		lastBlock := this.getNeoBlock(strconv.FormatUint(this.neoStartHeight-1, 10))
		this.neoNextConsensus = lastBlock.NextConsensus
	}

	for {
		// get current neo block height
		currentNeoHeight := this.getCurrentNeoHeight()
		err := this.neoToZion(this.neoStartHeight, currentNeoHeight)
		if err != nil {
			Log.Errorf("neoToZion error: %v", err)
		}
		err = this.db.PutNeoHeight(this.neoStartHeight) // this.neoStartHeight == currentNeoHeight
		if err != nil {

		}
		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second)
	}
}

func (this *SyncService) neoToZion(m, n uint64) error {
	for i := m; i < n; i++ {
		Log.Infof("[neoToZion] start processing neo block %d", i)
		response := this.neoSdk.GetBlock(strconv.Itoa(int(i)))
		if response.HasError() {
			return fmt.Errorf("neoSdk.GetBlockByIndex error: %s", response.GetErrorInfo())
		}
		blk := response.Result
		if blk.Hash == "" {
			return fmt.Errorf("neoSdk.GetBlockByIndex response is empty")
		}

		// check if this block contains cross chain tx
		txs := blk.Tx
		for _, tx := range txs {
			err := this.processNeoTx(tx, i)
			if err != nil {
				Log.Errorf("[neoToZion] processNeoTx error: %s, neoHeight: %d, neoTxHash: %s", err, i, tx.Hash)
			}
		}

		// if block.nextConsensus is changed, sync key header of NEO,
		// but should be done after all cross chain tx in this block are handled for verification purpose.
		if blk.NextConsensus != this.neoNextConsensus {
			latestHeight, err := this.GetLatestSyncHeightOnZion(this.config.NeoConfig.SideChainId)
			if err != nil {
				Log.Errorf("[neoToZion] GetLatestSyncHeightOnZion error: %s", err)
			}
			if i > latestHeight {
				Log.Infof("[neoToZion] sync key block header from neo: %d", blk.Index)
				err := this.syncHeaderToZion(blk)
				if err != nil {
					Log.Errorf("[neoToZion] syncHeaderToZion error: %s, neoHeight: %d", err, i)
				}
				this.neoNextConsensus = blk.NextConsensus
			}
		}

		this.neoStartHeight++
	}
	return nil
}
