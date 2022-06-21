package service

import (
	"github.com/joeqian10/neo3-gogogo/rpc"
	"github.com/joeqian10/neo3-gogogo/wallet"
	"github.com/polynetwork/neo3-relayer/config"
	"github.com/polynetwork/neo3-relayer/db"
	"github.com/polynetwork/neo3-relayer/log"
	"github.com/polynetwork/neo3-relayer/zion"
	"os"
)

var Log = log.Log

// SyncService ...
type SyncService struct {
	zionSdk         *zion.ZionTools
	zionPubKeys     [][]byte
	zionStartHeight uint64

	nwh               *wallet.WalletHelper
	neoSdk            *rpc.RpcClient
	neoAllowedMethods map[string]bool

	db     *db.BoltDB
	config *config.Config
}

// NewSyncService ...
func NewSyncService(zionSdk *zion.ZionTools, neoAccount *wallet.WalletHelper, client *rpc.RpcClient) *SyncService {
	if !checkIfExist(config.DefConfig.DBPath) {
		os.Mkdir(config.DefConfig.DBPath, os.ModePerm)
	}
	boltDB, err := db.NewBoltDB(config.DefConfig.DBPath)
	if err != nil {
		Log.Errorf("db.NewBoltDB error:%s", err)
		os.Exit(1)
	}
	am := make(map[string]bool)
	for _, m := range config.DefConfig.CustomConfig.AllowedMethods {
		am[m] = true
	}
	syncSvr := &SyncService{
		zionSdk:           zionSdk,
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
	go this.ZionToNeo()
	go this.ZionToNeoCheck()
}

func checkIfExist(dir string) bool {
	_, err := os.Stat(dir)
	if err != nil && !os.IsExist(err) {
		return false
	}
	return true
}
