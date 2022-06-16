package main

import (
	"fmt"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/joeqian10/neo3-gogogo/rpc"
	"github.com/joeqian10/neo3-gogogo/wallet"
	"github.com/polynetwork/neo3-relayer/zion"
	"github.com/polynetwork/poly/core/types"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/polynetwork/neo3-relayer/cmd"
	"github.com/polynetwork/neo3-relayer/config"
	"github.com/polynetwork/neo3-relayer/log"
	"github.com/polynetwork/neo3-relayer/service"

	relaySdk "github.com/polynetwork/poly-go-sdk"
	"github.com/urfave/cli"
)

var Log = log.Log

func setupApp() *cli.App {
	app := cli.NewApp()
	app.Usage = "NEO3 Relayer"
	app.Action = startSync
	app.Copyright = "Copyright in 2022 The NEO Project"
	app.Flags = []cli.Flag{
		cmd.LogLevelFlag,
		cmd.ConfigPathFlag,
		cmd.NeoPwd,
	}
	app.Commands = []cli.Command{}
	app.Before = func(context *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		return nil
	}
	return app
}

func main() {
	if err := setupApp().Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func startSync(ctx *cli.Context) {
	configPath := ctx.String(cmd.GetFlagName(cmd.ConfigPathFlag))
	err := config.DefConfig.Init(configPath)
	if err != nil {
		fmt.Println("DefConfig.Init error: ", err)
		return
	}

	neoPwd := ctx.GlobalString(cmd.GetFlagName(cmd.NeoPwd))

	//create zion sdk rpc client
	zionSdk := zion.NewZionTools(config.DefConfig.ZionConfig.RpcUrl)

	// create a NEO RPC client
	neoRpcClient := rpc.NewClient(config.DefConfig.NeoConfig.RpcUrl)

	// open the NEO wallet
	ps := helper.ProtocolSettings{
		Magic:          config.DefConfig.NeoConfig.NeoMagic,
		AddressVersion: helper.DefaultAddressVersion,
	}
	w, err := wallet.NewNEP6Wallet(config.DefConfig.NeoConfig.WalletFile, &ps, nil, nil)
	if err != nil {
		Log.Errorf("[NEO Relayer] Failed to open NEO wallet: %s", err)
		return
	}

	if neoPwd == "" {
		fmt.Println()
		fmt.Printf("Neo Wallet Password:")
		pwd, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			Log.Errorf("[NEO Relayer] Invalid password entered")
		}
		neoPwd = string(pwd)
		fmt.Println()
	}
	err = w.Unlock(neoPwd)
	if err != nil {
		Log.Errorf("[NEO Relayer] Failed to decrypt NEO account")
		return
	}
	wh := wallet.NewWalletHelperFromWallet(neoRpcClient, w)

	//Start syncing
	syncService := service.NewSyncService(zionSdk, wh, neoRpcClient)
	syncService.Run()

	waitToExit()
}

func waitToExit() {
	exit := make(chan bool, 0)
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sc {
			Log.Infof("Neo Relayer received exit signal: %v.", sig.String())
			close(exit)
			break
		}
	}()
	<-exit
}

func SetUpPoly(poly *relaySdk.PolySdk, rpcAddr string) error {
	poly.NewRpcClient().SetAddress(rpcAddr)
	c1 := make(chan *types.Header, 1)
	c2 := make(chan error, 1)

	// use another routine to check time out and error
	go func() {
		hdr, err := poly.GetHeaderByHeight(0)
		if err != nil {
			c2 <- err
		}
		c1 <- hdr
	}()

	select {
	case hdr := <- c1:
		poly.SetChainId(hdr.ChainID)
	case err := <- c2:
		return  err
	case <- time.After(time.Second * 5):
		return fmt.Errorf("poly rpc port timeout")
	}

	return nil
}
