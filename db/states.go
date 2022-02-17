package db

import (
	"fmt"
	"github.com/polynetwork/poly/common"
)

type Retry struct {
	Height  uint32
	TxHash  string
	Id      []byte
	Subject []byte
}

func (this *Retry) Serialization(sink *common.ZeroCopySink) {
	sink.WriteUint32(this.Height)
	sink.WriteString(this.TxHash)
	sink.WriteVarBytes(this.Id)
	sink.WriteVarBytes(this.Subject)
}

func (this *Retry) Deserialization(source *common.ZeroCopySource) error {
	height, eof := source.NextUint32()
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
