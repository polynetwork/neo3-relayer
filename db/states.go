package db

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
)

type NeoRecord struct {
	Height  uint64
	TxHash        string
	ToMerkleValue []byte
}

func (this *NeoRecord) Serialization(sink *common.ZeroCopySink) {
	sink.WriteUint64(this.Height)
	sink.WriteString(this.TxHash)
	sink.WriteVarBytes(this.ToMerkleValue)
}

func (this *NeoRecord) Deserialization(source *common.ZeroCopySource) error {
	height, eof := source.NextUint64()
	if eof {
		return fmt.Errorf("waiting deserialize height error")
	}
	txHash, eof := source.NextString()
	if eof {
		return fmt.Errorf("waiting deserialize txHash error")
	}
	subject, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("waiting deserialize subject error")
	}

	this.Height = height
	this.TxHash = txHash
	this.ToMerkleValue = subject

	return nil
}
