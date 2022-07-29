package service

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/native/go_abi/cross_chain_manager_abi"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/joeqian10/neo3-gogogo/keys"
	"github.com/joeqian10/neo3-gogogo/rpc"
	"github.com/joeqian10/neo3-gogogo/wallet"
	"github.com/polynetwork/neo3-relayer/config"
	"github.com/polynetwork/neo3-relayer/db"
	"github.com/polynetwork/neo3-relayer/log"
	"github.com/polynetwork/neo3-relayer/zion"
	"math/big"
	"os"
	"sync"
)

var Log = log.Log

// SyncService ...
type SyncService struct {
	zionChainId     *big.Int
	zionSigner      *zion.ZionSigner
	zionSdk         *zion.ZionTools
	zionCCM         *cross_chain_manager_abi.CrossChainManager
	zionCcmAddr     common.Address
	zionPubKeys     [][]byte
	zionStartHeight uint64

	neoSdk             *rpc.RpcClient
	neoKeyPair         *keys.KeyPair
	neoWalletHelper    *wallet.WalletHelper
	neoNextConsensus   string
	neoStartHeight     uint64
	neoStateRootHeight uint64
	neoAllowedMethods  map[string]bool

	db     *db.BoltDB
	config *config.Config
}

// NewSyncService ...
//func NewSyncService(zionSdk *zion.ZionTools, neoAccount *wallet.WalletHelper, client *rpc.RpcClient) *SyncService {
func NewSyncService(cfg *config.Config) *SyncService {
	s := &SyncService{config: cfg}
	// add zion client
	z := zion.NewZionTools(cfg.ZionConfig.RpcUrl)
	s.zionSdk = z

	// check chain id
	chainId, err := s.zionSdk.GetChainID() // use the first one
	if err != nil {
		panic(any("zionSdk.GetChainID error: " + err.Error()))
	}
	s.zionChainId = chainId

	// create a zion signer
	signer, err := zion.NewZionSigner(cfg.ZionConfig.NodeKey)
	if err != nil {
		panic(any(err))
	}
	s.zionSigner = signer

	// add zion ccmc
	s.zionCcmAddr = common.HexToAddress(cfg.ZionConfig.ECCMAddress)
	t, err := cross_chain_manager_abi.NewCrossChainManager(s.zionCcmAddr, z.GetEthClient())
	if err != nil {
		panic(any("NewCrossChainManager error: " + err.Error()))
	}
	s.zionCCM = t

	// neo rpc client
	c := rpc.NewClient(cfg.NeoConfig.RpcUrl)
	s.neoSdk = c

	// neo wallet
	ps := helper.ProtocolSettings{
		Magic:          cfg.NeoConfig.NeoMagic,
		AddressVersion: helper.DefaultAddressVersion,
	}
	w, err := wallet.NewNEP6Wallet(cfg.NeoConfig.WalletFile, &ps, nil, nil)
	if err != nil {
		panic(any("open neo wallet file error: " + err.Error()))
	}
	err = w.Unlock(cfg.NeoConfig.WalletPwd)
	if err != nil {
		panic(any("unlock neo wallet error: " + err.Error()))
	}
	if len(w.Accounts) == 0 {
		panic(any("neo wallet has no account"))
	}
	wh := wallet.NewWalletHelperFromWallet(c, w)
	s.neoWalletHelper = wh

	// neo key pair
	a := w.Accounts[0]
	pair, err := a.GetKeyFromPassword(cfg.NeoConfig.WalletPwd)
	if err != nil {
		panic(any("GetKeyFromPassword error: " + err.Error()))
	}
	s.neoKeyPair = pair

	// add allowed methods
	am := make(map[string]bool)
	for _, m := range config.DefConfig.CustomConfig.AllowedMethods {
		am[m] = true
	}

	// add db
	path := cfg.BoltDbPath
	if _, err := os.Stat(path); err != nil {
		Log.Infof("db path: %s does not exist, make dir", path)
		err := os.MkdirAll(path, 0711)
		if err != nil {
			panic(any(err))
		}
	}
	d, err := db.NewBoltDB(path)
	if err != nil {
		Log.Errorf("db.NewBoltDB error:%s", err)
		os.Exit(1)
	}
	s.db = d

	return s
}

// Start ...
func (this *SyncService) Start() {
	wg := new(sync.WaitGroup)
	//var wg sync.WaitGroup
	GoFunc(wg, this.NeoToZion)
	GoFunc(wg, this.ZionToNeo)
	GoFunc(wg, this.ZionToNeoCheck)
	wg.Wait()
}

// GoFunc runs a goroutine under WaitGroup
func GoFunc(routinesGroup *sync.WaitGroup, f func()) {
	routinesGroup.Add(1)
	go func() {
		defer routinesGroup.Done()
		f()
	}()
}
