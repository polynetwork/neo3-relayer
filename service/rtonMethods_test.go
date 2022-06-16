package service

import (
	goc "crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/joeqian10/neo3-gogogo/crypto"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/joeqian10/neo3-gogogo/rpc"
	"github.com/joeqian10/neo3-gogogo/rpc/models"
	"github.com/joeqian10/neo3-gogogo/sc"
	"github.com/ontio/ontology-crypto/keypair"
	relaySdk "github.com/polynetwork/poly-go-sdk"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	"github.com/polynetwork/poly/core/types"
	"github.com/stretchr/testify/assert"
	"log"
	"strconv"
	"testing"
)

func TestSyncService_GetCurrentNeoChainSyncHeight(t *testing.T) {
	height := 64
	//s := string(height) // ascii code
	s1 := strconv.Itoa(height)

	assert.Equal(t, "64", s1)
}

func Test0(t *testing.T) {
	x := byte(0x1b)
	y := int((x - 27) & ^byte(4))
	assert.Equal(t, 0, y)
}

func Test1(t *testing.T) {
	x := byte(0x1c)
	y := int((x - 27) & ^byte(4))
	assert.Equal(t, 1, y)
}

func Test_ConsensusPayload(t *testing.T) {
	//bs := []byte{}
	//ConsensusPayload := helper.HexToBytes("7b226c6561646572223a343239343936373239352c227672665f76616c7565223a22484a675171706769355248566745716354626e6443456c384d516837446172364e4e646f6f79553051666f67555634764d50675851524171384d6f38373853426a2b38577262676c2b36714d7258686b667a72375751343d222c227672665f70726f6f66223a22785864422b5451454c4c6a59734965305378596474572f442f39542f746e5854624e436667354e62364650596370382f55706a524c572f536a5558643552576b75646632646f4c5267727052474b76305566385a69413d3d222c226c6173745f636f6e6669675f626c6f636b5f6e756d223a343239343936373239352c226e65775f636861696e5f636f6e666967223a7b2276657273696f6e223a312c2276696577223a312c226e223a342c2263223a312c22626c6f636b5f6d73675f64656c6179223a31303030303030303030302c22686173685f6d73675f64656c6179223a31303030303030303030302c22706565725f68616e647368616b655f74696d656f7574223a31303030303030303030302c227065657273223a5b7b22696e646578223a312c226964223a2231323035303237613165326539616130626462366538333435633435653962643666333139656636323439396638383638366361663563616239613034616631663131343266227d2c7b22696e646578223a322c226964223a2231323035303234356261346534623033613365396665643737616533356163303065363930613564653464393061343938343666613331666535663135363837373734613338227d2c7b22696e646578223a332c226964223a2231323035303335363435396366653165336636663032626535306637396230306562613934323531323138663162356237653030313231646264653032616139663066363933227d2c7b22696e646578223a342c226964223a2231323035303234346266343036396461333332613138383566353262636161623563643231626336646130643834626333373433613232353666663464633335663566343738227d5d2c22706f735f7461626c65223a5b322c322c332c332c342c332c312c322c332c332c312c342c332c342c312c312c312c312c342c332c322c312c332c322c312c322c332c322c312c322c322c342c332c312c342c342c312c312c322c332c322c332c322c342c322c322c342c322c332c312c342c342c342c342c332c312c342c342c312c335d2c226d61785f626c6f636b5f6368616e67655f76696577223a33307d7d")
	//blkInfo := &vconfig.VbftBlockInfo{}
	//_ = json.Unmarshal(ConsensusPayload, blkInfo) // already checked before
	//if blkInfo.NewChainConfig != nil {
	//	for _, peer := range blkInfo.NewChainConfig.Peers {
	//		keyBytes, _ := hex.DecodeString(peer.ID)
	//		key, _ := keypair.DeserializePublicKey(keyBytes) // compressed
	//		uncompressed := getRelayUncompressedKey(key)
	//		bs = append(bs, uncompressed...)
	//	}
	//}
	//
	//log.Infof("public keys hex string: ", helper.BytesToHex(bs))
}

func TestPolyPublicKey(t *testing.T) {
	polyPubKeyStrings := []string{
		"1205042092e34e0176dccf8abb496b833d591d25533469b3caf0e279b9742955dd8fc3899a042cd338e82698b5284720f85b309f2b711c05cb37836488371741168da6",
		"120504696c0cbe74f01ee85e3c0ebe4ebdc5bea404f199d0262f1941fd39ff0d100257a2f2a11aaf2f0baccf6c9e30aa3b204bd4b935f3c1bb5b20349c7afd35565f2e",
		"1205047bd771e68adb88398282e21a8b03c12f64c2351ea49a2ba06a0327c83b239ca9420cf3852f7991d2a53afd008d1f6c356294b83aeeb4aad769f8c95ffeb4d5ac",
		"1205048247efcfeae0fdf760685d1ac1c083be3ff5e9a4a548bc3a2e98f0434f092483760cb1d3138a9beadf9f784d60604f37f1a51464ba228ec44f89879df1c10e07",
		"120504a4f44dd65cbcc52b1d1ac51747378a7f84753b5f7bf2760ca21390ced6b172bbf4d03e2cf4e0e79e46f7a757058d240e542853341e88feb1610ff03ba785cfc1",
		"120504d0d0e883c73d8256cf4314822ddd973c0179b73d8ed3df85aad38d36a8b2b0c7696f0c66330d243b1bc7bc8d05e694b4d642ac68f741d2b7f6ea4037ef46b992",
		"120504ef44beba84422bd76a599531c9fe50969a929a0fee35df66690f370ce19fa8c00ed4b649691d116b7deeb79b714156d18981916e58ae40c0ebacbf3bd0b87877"}
	polyPubKeys := make([][]byte, len(polyPubKeyStrings))
	for i, ppks := range polyPubKeyStrings {
		polyPubKeys[i] = helper.HexToBytes(ppks)
	}
	//polyPubKeyBytes := helper.HexToBytes("1205042092e34e0176dccf8abb496b833d591d25533469b3caf0e279b9742955dd8fc3899a042cd338e82698b5284720f85b309f2b711c05cb37836488371741168da6120504696c0cbe74f01ee85e3c0ebe4ebdc5bea404f199d0262f1941fd39ff0d100257a2f2a11aaf2f0baccf6c9e30aa3b204bd4b935f3c1bb5b20349c7afd35565f2e1205047bd771e68adb88398282e21a8b03c12f64c2351ea49a2ba06a0327c83b239ca9420cf3852f7991d2a53afd008d1f6c356294b83aeeb4aad769f8c95ffeb4d5ac1205048247efcfeae0fdf760685d1ac1c083be3ff5e9a4a548bc3a2e98f0434f092483760cb1d3138a9beadf9f784d60604f37f1a51464ba228ec44f89879df1c10e07120504a4f44dd65cbcc52b1d1ac51747378a7f84753b5f7bf2760ca21390ced6b172bbf4d03e2cf4e0e79e46f7a757058d240e542853341e88feb1610ff03ba785cfc1120504d0d0e883c73d8256cf4314822ddd973c0179b73d8ed3df85aad38d36a8b2b0c7696f0c66330d243b1bc7bc8d05e694b4d642ac68f741d2b7f6ea4037ef46b992120504ef44beba84422bd76a599531c9fe50969a929a0fee35df66690f370ce19fa8c00ed4b649691d116b7deeb79b714156d18981916e58ae40c0ebacbf3bd0b87877")

	sigList := []string{
		"011cd4e5cd55eff0dc21b9d915ce7c7132dd79dff4af70f5ddf732b667b57c163a9b72e0c04a31cd7bd825ce46c0895b2ca2866222bb8c36c39029279fa7b0ced3e5",
		"011b9a1a8b6795ec5e1bdb8366d718d76b6021a76faf018fa18ac19409838e98b1332a00e26d97c502917fa855cf351c6e0d17205cec47204a94d6627d00dd474cad",
		"011bad1b608402de149b2efd5f4bd00bf65ef58c268601601a47b6275149f3271bc853236b7b41b7e7996dd9d8704fbad8f11fa19e7b7ed902ac8739ad45e979484d",
		"011b73e860ec2ac329554b800ec12d4e362b515695a5e445bafc416b043efb08241627db846bc8cbb205871d0e28de46cde714c728c1b3a2332295cb7099345060f1",
		"011b550f1ead1491093ce2a44c49fb0a76ab88ff398e3238722f80bf0c741eda97687648db9a704c59459a7121f57034fe7237d007c3b24b41651e6e319e9908e01e"}
	sigs := make([][]byte, len(sigList))
	for i, sig := range sigList {
		sigs[i] = helper.HexToBytes(sig)
	}

	block1Hash := helper.HexToBytes("0166e16468912048e9136bd2dd4510e080ed574deb7d30defb0ce17b93b5377d")
	hasher := goc.SHA256.New()
	hasher.Write(block1Hash)
	digest := hasher.Sum(nil)

	newSigs, err :=  sortSignatures(polyPubKeys, sigs, digest)
	assert.Nil(t, err)
	fmt.Println(helper.BytesToHex(newSigs))
}

func TestRecoverPublicKeys(t *testing.T)  {
	pubKeyBytes := helper.HexToBytes("1205042092e34e0176dccf8abb496b833d591d25533469b3caf0e279b9742955dd8fc3899a042cd338e82698b5284720f85b309f2b711c05cb37836488371741168da6120504696c0cbe74f01ee85e3c0ebe4ebdc5bea404f199d0262f1941fd39ff0d100257a2f2a11aaf2f0baccf6c9e30aa3b204bd4b935f3c1bb5b20349c7afd35565f2e1205047bd771e68adb88398282e21a8b03c12f64c2351ea49a2ba06a0327c83b239ca9420cf3852f7991d2a53afd008d1f6c356294b83aeeb4aad769f8c95ffeb4d5ac1205048247efcfeae0fdf760685d1ac1c083be3ff5e9a4a548bc3a2e98f0434f092483760cb1d3138a9beadf9f784d60604f37f1a51464ba228ec44f89879df1c10e07120504a4f44dd65cbcc52b1d1ac51747378a7f84753b5f7bf2760ca21390ced6b172bbf4d03e2cf4e0e79e46f7a757058d240e542853341e88feb1610ff03ba785cfc1120504d0d0e883c73d8256cf4314822ddd973c0179b73d8ed3df85aad38d36a8b2b0c7696f0c66330d243b1bc7bc8d05e694b4d642ac68f741d2b7f6ea4037ef46b992120504ef44beba84422bd76a599531c9fe50969a929a0fee35df66690f370ce19fa8c00ed4b649691d116b7deeb79b714156d18981916e58ae40c0ebacbf3bd0b87877")
	pubKeys := recoverPublicKeys(pubKeyBytes)
	assert.Equal(t, 7, len(pubKeys))
}

func TestRecoverPublicKeysFromSigs(t *testing.T) {
	//pubKeys := []string{
	//	"120503 8b8af6210ecfdcbcab22552ef8d8cf41c6f86f9cf9ab53d865741cfdb833f06b",
	//	"120503 1e0779f5c5ccb2612352fe4a200f99d3e7758e70ba53f607c59ff22a30f678ff",
	//	"120502 8172918540b2b512eae1872a2a2e3a28d989c60d95dab8829ada7d7dd706d658",
	//	"120502 679930a42aaf3c69798ca8a3f12e134c019405818d783d11748e039de8515988",
	//	"120502 eb1baab602c5899282561cdaaa7aabbcdd0ccfcbc3e79793ac24acf90778f35a",
	//}
	sigStrings := []string{
		"011b55d76afdd366f48834490d60662b81d340d1736e710601967ae725d9350d70816c2019873d2b57fd11601960cc330b726719cc7fae60e3f2a8b6900885bbc7fc",
		"011c4e701beab5309c369d9132516ea15356ed17b8f287127b3c63fbc8be00feb82e1771889f5f8ca0a5c9b5db0b642b1ab08e50dc05c59d64d2cd51f9b5ec3fb0eb",
		"011c7d7002d90425c0b309424a8334a50e37334b464581d4b25538832074baab8aba7da1fc77044d1fc82689ee36b349b4965ba843d035dba28122e19bd88f13d73c",
		"011b654645b460df6dbf7bdeda16b49fabbbfb1d6d882c47b76061203f3713fc621420c978ebec291e1386c7b9026577bfb862e2260ecc4347eca713ec94fe55c72b",
		"011cc2d1b99de8b3d7c6bf245ad9382fb93cb006e83b391459846920637ee082bf8f02934517ed9c703cad41ba8143fc05b4e7a2a50a46313d182d864a17443089e5",
	}

	block1Hash := helper.ReverseBytes(helper.HexToBytes("4d46bff66a8d537f8bfd0e3b0db6b97cfef409ebfde46d3b9b005ff7f5505843"))
	//block1Hash := helper.ReverseBytes(helper.HexToBytes("deed76ac3f5e69f9e1040e4390202059bd11fcde7c05c75574155fa24e7b4a5c"))
	hasher := goc.SHA256.New()
	hasher.Write(block1Hash)
	digest := hasher.Sum(nil)
	log.Println(helper.BytesToHex(digest))

	sigs := make([][]byte, len(sigStrings))
	for i, ss := range sigStrings {
		sigs[i] = helper.HexToBytes(ss)
		pubKey, err := recoverPublicKeyFromSignature(sigs[i], digest)
		assert.Nil(t, err)
		log.Println(helper.BytesToHex(pubKey))
	}
}

func TestGetBookKeepers(t *testing.T)  {
	scriptHash, err := helper.UInt160FromString("0x233e50e8f9c22563dc4873230a49d6931c2adebe") // hex string in little endian
	assert.Nil(t, err)
	script, err := sc.MakeScript(scriptHash, GET_BOOK_KEEPERS, []interface{}{})
	assert.Nil(t, err)
	log.Println(crypto.Base64Encode(script))

	client := rpc.NewClient("http://seed1t.neo.org:21332")
	response := client.InvokeScript(crypto.Base64Encode(script), nil)

	if len(response.Result.Stack) == 0 {
		panic("[getBookKeeps] InvokeScript response stack incorrect length")
	}
	stack0 := response.Result.Stack[0] // Array of ByteArray
	stack0.Convert()
	if stack0.Type != "Array" {
		panic("[getBookKeeps] InvokeScript response stack incorrect type")
	}
	values := stack0.Value.([]models.InvokeStack)

	pubKeys := make([][]byte, len(values))
	for i, v := range values {
		if v.Type != "ByteString" {
			panic("[getBookKeeps] InvokeScript response inside stack incorrect type")
		}
		s, err := crypto.Base64Decode(v.Value.(string))
		pubKey, err := crypto.NewECPointFromString(helper.BytesToHex(s))
		assert.Nil(t, err)
		pubKeys[i] = pubKey.EncodePoint(false) // length 65
	}
}

func TestConvertPublicKey(t *testing.T)  {
	pubKeyBytes := helper.HexToBytes("041e0779f5c5ccb2612352fe4a200f99d3e7758e70ba53f607c59ff22a30f678ff757519efff911efc7ed326890a2752b9456cc0054f9b63215f1d616e574d6197")
	p, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	assert.Nil(t, err)
	log.Println(helper.BytesToHex(p.SerializeCompressed()))
}

func Test666(t *testing.T)  {
	c := rpc.NewClient("http://seed1t.neo.org:20332")
	r1 := c.GetRawTransaction("0x58f6b0fe73e1b6b68bd604ab6f2d06b816a6cfb96540db8b3b87b0987df99e1d")
	blockHash := r1.Result.BlockHash
	r2 := c.GetBlockHeader(blockHash)
	index := r2.Result.Index
	log.Println(index)
}

func Test777(t *testing.T) {
	polyRpc := "http://beta1.poly.network:20336"
	rc := relaySdk.NewPolySdk()
	rc.NewRpcClient().SetAddress(polyRpc)

	block, err := rc.GetBlockByHeight(60000)
	assert.Nil(t, err)

	blkInfo := &vconfig.VbftBlockInfo{}
	_ = json.Unmarshal(block.Header.ConsensusPayload, blkInfo) // already checked before
	if blkInfo.NewChainConfig != nil {
		var bookkeepers []keypair.PublicKey
		for _, peer := range blkInfo.NewChainConfig.Peers {
			keyBytes, _ := hex.DecodeString(peer.ID)
			key, _ := keypair.DeserializePublicKey(keyBytes) // compressed
			bookkeepers = append(bookkeepers, key)
		}

		nb, err := types.AddressFromBookkeepers(bookkeepers)
		assert.Nil(t, err)
		log.Println(nb.ToHexString())
	}
}
