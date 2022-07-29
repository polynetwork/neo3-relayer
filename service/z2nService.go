package service

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"time"
)

// ZionToNeo syncs from zion to neo
func (this *SyncService) ZionToNeo() {
	this.zionStartHeight = this.getZionStartHeight() // means the next zion height to be synced
	for {
		currentZionHeight := this.getCurrentZionHeight()
		err := this.zionToNeo(this.zionStartHeight, currentZionHeight)
		if err != nil {
			Log.Errorf("[ZionToNeo] zionToNeo error: %v", err)
		}
		err = this.db.PutZionHeight(this.zionStartHeight) // this.zionStartHeight == currentZionHeight
		if err != nil {
			Log.Errorf("[ZionToNeo] db.PutZionHeight error: %v", err)
		}
		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second)
	}
}

func (this *SyncService) zionToNeo(m, n uint64) error {
	for i := m; i < n; i++ {
		Log.Infof("processing zion block %d", i)

		opt := &bind.FilterOpts{
			Start:   i,
			End:     &i,
			Context: context.Background(),
		}

		events, err := this.zionCCM.FilterMakeProof(opt)
		if err != nil {
			return fmt.Errorf("FilterMakeProof error: %s", err)
		}

		if events == nil {
			return nil
		}

		for events.Next() {
			evt := events.Event
			err = this.processZionTx(evt, i)
			if err != nil {
				Log.Errorf("processZionTx error: %v of hash: %s at height: %d", err, evt.Raw.TxHash.String(), i)
			}
		}

		//// no need to change epoch
		//if this.config.ZionConfig.ChangeEpoch {
		//	// sync key header, change epoch,
		//	// but should be done after all cross chain tx in this block are handled for verification purpose.
		//	header, err := this.zionSdk.GetBlockHeader(i)
		//	if err != nil {
		//		return fmt.Errorf("GetBlockHeader error: %s", err)
		//	}
		//
		//	err = this.changeEpoch(header)
		//	if err != nil {
		//		Log.Errorf("--------------------------------------------------")
		//		Log.Errorf("changeEpoch error: %s at zion height: %d", err, i)
		//		Log.Errorf("--------------------------------------------------")
		//	}
		//}

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
