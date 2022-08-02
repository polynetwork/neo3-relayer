package service

import (
	"github.com/joeqian10/neo3-gogogo/helper"
	"gotest.tools/assert"
	"testing"
)

func TestBigInt(t *testing.T)  {
	b := "c800"
	i := helper.BigIntFromNeoBytes(helper.HexToBytes(b))
	assert.Equal(t, uint64(200), i.Uint64())
}
