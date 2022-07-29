package zion

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/contracts/native/governance/node_manager"
	"github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

//var Log = log.Log

type ZionTools struct {
	rpcClient  *rpc.Client
	restClient *RestClient
	ethClient  *ethclient.Client
}

type jsonError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type heightReq struct {
	JsonRpc string   `json:"jsonrpc"`
	Method  string   `json:"method"`
	Params  []string `json:"params"`
	Id      uint     `json:"id"`
}

type heightRep struct {
	JsonRpc string     `json:"jsonrpc"`
	Result  string     `json:"result"`
	Error   *jsonError `json:"error,omitempty"`
	Id      uint       `json:"id"`
}

type BlockReq struct {
	JsonRpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	Id      uint          `json:"id"`
}

type BlockRep struct {
	JsonRPC string        `json:"jsonrpc"`
	Result  *types.Header `json:"result"`
	Error   *jsonError    `json:"error,omitempty"`
	Id      uint          `json:"id"`
}

type proofReq struct {
	JsonRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	Id      uint          `json:"id"`
}

type proofRsp struct {
	JsonRPC string     `json:"jsonrpc"`
	Result  ETHProof   `json:"result,omitempty"`
	Error   *jsonError `json:"error,omitempty"`
	Id      uint       `json:"id"`
}

type ETHProof struct {
	Address       string         `json:"address"`
	Balance       string         `json:"balance"`
	CodeHash      string         `json:"codeHash"`
	Nonce         string         `json:"nonce"`
	StorageHash   string         `json:"storageHash"`
	AccountProof  []string       `json:"accountProof"`
	StorageProofs []StorageProof `json:"storageProof"`
}

type StorageProof struct {
	Key   string   `json:"key"`
	Value string   `json:"value"`
	Proof []string `json:"proof"`
}

func NewZionTools(url string) *ZionTools {
	rpcClient, _ := rpc.Dial(url)
	ec, err := ethclient.Dial(url)
	if err != nil {
		panic(any(fmt.Errorf("NewZionTools: cannot dial sync node, err: %v", err)))
	}
	rc := NewRestClient()
	rc.SetAddr(url)
	tool := &ZionTools{
		rpcClient: rpcClient,
		restClient: rc,
		ethClient:  ec,
	}
	return tool
}

func (self *ZionTools) GetEthClient() *ethclient.Client {
	return self.ethClient
}

func (self *ZionTools) GetStorage(contract common.Address, key []byte) (data []byte, err error) {
	var result hexutil.Bytes
	keyHex := hex.EncodeToString(key)
	err = self.rpcClient.CallContext(context.Background(), &result, "eth_getStorageAtCacheDB", contract, keyHex, "latest")
	return result, err
}

func (self *ZionTools) GetRawHeaderAndRawSeals(height uint64) (rawHeader, rawSeals []byte, err error) {
	header, err := self.GetBlockHeader(height)
	if err != nil {
		return
	}
	rawHeader, err = rlp.EncodeToBytes(types.HotstuffFilteredHeader(header, false))
	extra, err := types.ExtractHotstuffExtra(header)
	if err != nil {
		return
	}
	rawSeals, err = rlp.EncodeToBytes(extra.CommittedSeal)
	return
}

func (self *ZionTools) GetEpochInfo() (epochInfo *node_manager.EpochInfo, err error) {
	node_manager.InitABI()
	payload, err := new(node_manager.MethodEpochInput).Encode()
	if err != nil {
		return
	}
	arg := ethereum.CallMsg{
		From: common.Address{},
		To:   &utils.NodeManagerContractAddress,
		Data: payload,
	}
	res, err := self.GetEthClient().CallContract(context.Background(), arg, nil)
	if err != nil {
		return
	}
	output := new(node_manager.MethodEpochOutput)
	if err = output.Decode(res); err != nil {
		return
	}
	epochInfo = output.Epoch
	return
}

func (self *ZionTools) GetNodeHeight() (uint64, error) {
	req := &heightReq{
		JsonRpc: "2.0",
		Method:  "eth_blockNumber",
		Params:  make([]string, 0),
		Id:      1,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight: marshal req err: %s", err)
	}
	resp, err := self.restClient.SendRestRequest(data)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight err: %s", err)
	}
	rep := &heightRep{}
	err = json.Unmarshal(resp, rep)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight, unmarshal resp err: %s", err)
	}
	if rep.Error != nil {
		return 0, fmt.Errorf("GetNodeHeight, unmarshal resp err: %s", rep.Error.Message)
	}
	height, err := strconv.ParseUint(rep.Result, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight, parse resp height %s failed", rep.Result)
	} else {
		return height, nil
	}
}

func (self *ZionTools) GetBlockHeader(height uint64) (*types.Header, error) {
	params := []interface{}{fmt.Sprintf("0x%x", height), true}
	req := &BlockReq{
		JsonRpc: "2.0",
		Method:  "eth_getBlockByNumber",
		Params:  params,
		Id:      1,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("GetBlockHeader: marshal req err: %s", err)
	}
	resp, err := self.restClient.SendRestRequest(data)
	if err != nil {
		return nil, fmt.Errorf("GetBlockHeader err: %s", err)
	}
	rsp := &BlockRep{}
	err = json.Unmarshal(resp, rsp)
	if err != nil {
		return nil, fmt.Errorf("GetBlockHeader, unmarshal resp err: %s", err)
	}
	if rsp.Error != nil {
		return nil, fmt.Errorf("GetBlockHeader, unmarshal resp err: %s", rsp.Error.Message)
	}

	return rsp.Result, nil
}

func (self *ZionTools) GetChainID() (*big.Int, error) {
	return self.ethClient.ChainID(context.Background())
}

func (self *ZionTools) GetRawProof(address, key string, height uint64) (accountProof, storageProof []byte, err error) {
	height_hex := "0x" + strconv.FormatUint(height, 16)
	raw, err := self.GetProof(
		address,
		key,
		height_hex)
	if err != nil {
		return
	}
	res := &ETHProof{}
	err = json.Unmarshal(raw, res)
	if err != nil {
		return
	}
	accountProof, err = rlpEncodeStringList(res.AccountProof)
	if err != nil {
		return
	}
	storageProof, err = rlpEncodeStringList(res.StorageProofs[0].Proof)
	if err != nil {
		return
	}
	return
}

func (self *ZionTools) GetProof(contractAddress string, key string, blockheight string) ([]byte, error) {
	req := &proofReq{
		JsonRPC: "2.0",
		Method:  "eth_getProof",
		Params:  []interface{}{contractAddress, []string{key}, blockheight},
		Id:      1,
	}
	reqdata, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("get_ethproof: marshal req err: %s", err)
	}
	rspdata, err := self.restClient.SendRestRequest(reqdata)
	if err != nil {
		return nil, fmt.Errorf("GetProof: send request err: %s", err)
	}
	rsp := &proofRsp{}
	err = json.Unmarshal(rspdata, rsp)
	if err != nil {
		return nil, fmt.Errorf("GetProof, unmarshal resp err: %s", err)
	}
	if rsp.Error != nil {
		return nil, fmt.Errorf("GetProof, unmarshal resp err: %s", rsp.Error.Message)
	}
	result, err := json.Marshal(rsp.Result)
	if err != nil {
		return nil, fmt.Errorf("GetProof, Marshal result err: %s", err)
	}
	//fmt.Printf("proof res is:%s\n", string(result))
	return result, nil
}

func (self *ZionTools) WaitTransactionConfirm(hash common.Hash) bool {
	start := time.Now()
	for {
		if time.Now().After(start.Add(time.Minute * 1)) {
			return false
		}
		time.Sleep(time.Second * 1)
		_, ispending, err := self.GetEthClient().TransactionByHash(context.Background(), hash)
		if err != nil {
			continue
		}
		log.Debugf("eth_transaction %s is pending: %v", hash.String(), ispending)
		if ispending == true {
			continue
		} else {
			receipt, err := self.GetEthClient().TransactionReceipt(context.Background(), hash)
			if err != nil {
				continue
			}
			return receipt.Status == types.ReceiptStatusSuccessful
		}
	}
}

func GetEpochKey(epochID uint64) common.Hash {
	key := epochProofKey(EpochProofHash(epochID))
	return crypto.Keccak256Hash(key[common.AddressLength:])
}

var SKP_PROOF = "st_proof"
var EpochProofDigest = common.HexToHash("e4bf3526f07c80af3a5de1411dd34471c71bdd5d04eedbfa1040da2c96802041")

func epochProofKey(proofHashKey common.Hash) []byte {
	return utils.ConcatKey(utils.NodeManagerContractAddress, []byte(SKP_PROOF), proofHashKey.Bytes())
}

func EpochProofHash(epochID uint64) common.Hash {
	enc := EpochProofDigest.Bytes()
	enc = append(enc, utils.GetUint64Bytes(epochID)...)
	return crypto.Keccak256Hash(enc)
}

func GetRawEpochInfo(id, startHeight uint64, peers *node_manager.Peers) (rawEpochInfo []byte, err error) {
	var inf = struct {
		ID          uint64
		Peers       *node_manager.Peers
		StartHeight uint64
	}{
		ID:          id,
		Peers:       peers,
		StartHeight: startHeight,
	}
	return rlp.EncodeToBytes(inf)
}

func rlpEncodeStringList(raw []string) ([]byte, error) {
	var rawBytes []byte
	for i := 0; i < len(raw); i++ {
		rawBytes = append(rawBytes, common.Hex2Bytes(raw[i][2:])...)
		// rawBytes = append(rawBytes, common.Hex2Bytes(raw[i][2:]))
	}
	return rlp.EncodeToBytes(rawBytes)
}

type RestClient struct {
	addr       string
	restClient *http.Client
	user       string
	passwd     string
}

func NewRestClient() *RestClient {
	return &RestClient{
		restClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   5,
				DisableKeepAlives:     false,
				IdleConnTimeout:       time.Second * 300,
				ResponseHeaderTimeout: time.Second * 300,
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: time.Second * 300,
		},
	}
}

func (self *RestClient) SetAddr(addr string) *RestClient {
	self.addr = addr
	return self
}

func (self *RestClient) SetAuth(user string, passwd string) *RestClient {
	self.user = user
	self.passwd = passwd
	return self
}

func (self *RestClient) SetRestClient(restClient *http.Client) *RestClient {
	self.restClient = restClient
	return self
}

func (self *RestClient) SendRestRequest(data []byte) ([]byte, error) {
	resp, err := self.restClient.Post(self.addr, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("http post request:%s error:%s", data, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read rest response body error:%s", err)
	}
	return body, nil
}

func (self *RestClient) SendRestRequestWithAuth(data []byte) ([]byte, error) {
	url := self.addr
	bodyReader := bytes.NewReader(data)
	httpReq, err := http.NewRequest("POST", url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("SendRestRequestWithAuth - build http request error:%s", err)
	}
	httpReq.Close = true
	httpReq.Header.Set("Content-Type", "application/json")

	httpReq.SetBasicAuth(self.user, self.passwd)

	rsp, err := self.restClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("SendRestRequestWithAuth - http post error:%s", err)
	}
	defer rsp.Body.Close()
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil || len(body) == 0 {
		return nil, fmt.Errorf("SendRestRequestWithAuth - read rest response body error:%s", err)
	}
	return body, nil
}

