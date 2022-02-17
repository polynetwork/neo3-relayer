package service

import (
	"github.com/joeqian10/neo3-gogogo/rpc"
	"github.com/joeqian10/neo3-gogogo/wallet"
	"github.com/polynetwork/neo3-relayer/config"
	"github.com/polynetwork/neo3-relayer/db"
	"github.com/polynetwork/neo3-relayer/log"
	sdk "github.com/polynetwork/poly-go-sdk"
	"os"
)

var Log = log.Log

// SyncService ...
type SyncService struct {
	polySdk         *sdk.PolySdk
	polyPubKeys     [][]byte
	polyStartHeight uint32

	nwh               *wallet.WalletHelper
	neoSdk            *rpc.RpcClient
	neoAllowedMethods map[string]bool

	db     *db.BoltDB
	config *config.Config
}

// NewSyncService ...
func NewSyncService(polySdk *sdk.PolySdk, neoAccount *wallet.WalletHelper, client *rpc.RpcClient) *SyncService {
	if !checkIfExist(config.DefConfig.DBPath) {
		os.Mkdir(config.DefConfig.DBPath, os.ModePerm)
	}
	boltDB, err := db.NewBoltDB(config.DefConfig.DBPath)
	if err != nil {
		Log.Errorf("db.NewBoltDB error:%s", err)
		os.Exit(1)
	}
	am := make(map[string]bool)
	for _, m := range config.DefConfig.NeoConfig.AllowedMethods {
		am[m] = true
	}
	syncSvr := &SyncService{
		polySdk:           polySdk,
		neoSdk:            client,
		nwh:               neoAccount,
		neoAllowedMethods: am,
		db:                boltDB,
		config:            config.DefConfig,
	}
	return syncSvr
}

// Run ...
func (this *SyncService) Run() {
	go this.RelayToNeo()
	go this.RelayToNeoCheckAndRetry()
}

func checkIfExist(dir string) bool {
	_, err := os.Stat(dir)
	if err != nil && !os.IsExist(err) {
		return false
	}
	return true
}

func (this *SyncService) IsAllowedMethod(m string) bool {
	return this.neoAllowedMethods[m]
}
