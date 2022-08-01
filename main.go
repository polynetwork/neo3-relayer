package main

import (
	"fmt"
	"github.com/polynetwork/neo3-relayer/cmd"
	"github.com/polynetwork/neo3-relayer/config"
	"github.com/polynetwork/neo3-relayer/log"
	"github.com/polynetwork/neo3-relayer/service"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"os/signal"
	"runtime"
	"syscall"

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
	// get neo pwd
	neoPwd := config.DefConfig.NeoConfig.WalletPwd
	if neoPwd == "" {
		neoPwd = ctx.GlobalString(cmd.GetFlagName(cmd.NeoPwd))
	}
	for neoPwd == "" {
		fmt.Println()
		fmt.Printf("please enter neo wallet password:")
		pwd, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			Log.Errorf("invalid password entered")
			continue
		}
		neoPwd = string(pwd)
		fmt.Println()
	}
	config.DefConfig.NeoConfig.WalletPwd = neoPwd

	// create SyncService
	service.NewSyncService(config.DefConfig).Start()

	waitToExit()
}

func waitToExit() {
	exit := make(chan bool, 0)
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sc {
			Log.Infof("neo relayer received exit signal: %v.", sig.String())
			close(exit)
			break
		}
	}()
	<-exit
}
