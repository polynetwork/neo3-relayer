package db

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
)

type Record struct {
	Height  uint64
	TxHash  string
	Id      []byte
	Subject []byte
}

func (this *Record) Serialization(sink *common.ZeroCopySink) {
	sink.WriteUint64(this.Height)
	sink.WriteString(this.TxHash)
	sink.WriteVarBytes(this.Id)
	sink.WriteVarBytes(this.Subject)
}

func (this *Record) Deserialization(source *common.ZeroCopySource) error {
	height, eof := source.NextUint64()
	if eof {
		return fmt.Errorf("waiting deserialize height error")
	}
	txHash, eof := source.NextString()
	if eof {
		return fmt.Errorf("waiting deserialize txHash error")
	}
	id, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("waiting deserialize id error")
	}
	subject, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("waiting deserialize subject error")
	}

	this.Height = height
	this.TxHash = txHash
	this.Id = id
	this.Subject = subject

	return nil
}
