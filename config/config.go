package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

const (
	DEFAULT_CONFIG_FILE_NAME = "./config.json"
	DEFAULT_LOG_LEVEL        = 2
)

//Config object
type Config struct {
	PolyConfig    PolyConfig
	NeoConfig     NeoConfig
	ForceConfig   ForceConfig
	ScanInterval  uint64
	RetryInterval uint64
	DBPath        string
}

type PolyConfig struct {
	RpcUrl           string
	ChangeBookkeeper bool
}

type NeoConfig struct {
	SideChainID    uint64
	NeoMagic       uint32
	WalletFile     string
	RpcUrl         string
	CCMC           string // big endian string, like 0x1234567812345678123456781234567812345678
	P2NContract    string // poly to neo contract
	AllowedMethods []string
}

type ForceConfig struct {
	PolyStartHeight uint32
}

//Default config instance
var DefConfig = NewConfig()

//NewConfig retuen a TestConfig instance
func NewConfig() *Config {
	return &Config{}
}

//Init TestConfig with a config file
func (this *Config) Init(fileName string) error {
	err := this.loadConfig(fileName)
	if err != nil {
		return fmt.Errorf("loadConfig error:%s", err)
	}
	return nil
}

func (this *Config) loadConfig(fileName string) error {
	data, err := this.readFile(fileName)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, this)
	if err != nil {
		return fmt.Errorf("json.Unmarshal TestConfig:%s error:%s", data, err)
	}
	return nil
}

func (this *Config) readFile(fileName string) ([]byte, error) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("OpenFile %s error %s", fileName, err)
	}
	defer func() {
		err := file.Close()
		if err != nil {
			fmt.Println(fmt.Errorf("file %s close error %s", fileName, err))
		}
	}()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadAll %s error %s", fileName, err)
	}
	return data, nil
}
