package service

import (
	"encoding/json"
	"fmt"
	relaySdk "github.com/polynetwork/poly-go-sdk"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	"log"
	"testing"
	"time"
)

func TestSyncService_RelayToNeo(t *testing.T) {
	polyRpc := "http://beta1.poly.network:20336"
	rc := relaySdk.NewPolySdk()
	rc.NewRpcClient().SetAddress(polyRpc)

	i := uint32(4047)
	for true{
		log.Println(i)
		block, _ := rc.GetBlockByHeight(i)
		//assert.Nil(t, err)

		blkInfo := &vconfig.VbftBlockInfo{}
		_ = json.Unmarshal(block.Header.ConsensusPayload, blkInfo)
		//assert.Nil(t, err)

		if blkInfo.NewChainConfig != nil {
			break
		}
		i++
	}
}

func TestSyncService_RelayToNeo2(t *testing.T) {
	for i:=10000;i<100000;i+=10000 {
		go scan(i/10000, uint32(i), uint32(i+10000))
	}
	time.Sleep(10000*time.Second)
}

func scan(threadN int, from, to uint32)  {
	polyRpc := "http://beta1.poly.network:20336"
	rc := relaySdk.NewPolySdk()
	rc.NewRpcClient().SetAddress(polyRpc)

	for i:= from;i<to;i++ {
		block, err := rc.GetBlockByHeight(i)
		if err != nil {
			log.Println(err)
		}
		n := block.Header.Height
		_, _ = fmt.Printf("thread: %d, block: %d\n", threadN, n)

		blkInfo := &vconfig.VbftBlockInfo{}
		_ = json.Unmarshal(block.Header.ConsensusPayload, blkInfo)
		//assert.Nil(t, err)

		if blkInfo.NewChainConfig != nil {
			_, _ = fmt.Printf("found!!! thread: %d, block: %d\n", threadN, n)
			break
		}
	}
}
