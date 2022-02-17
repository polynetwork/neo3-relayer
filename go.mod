module github.com/polynetwork/neo3-relayer

go 1.17

require (
	github.com/boltdb/bolt v1.3.1
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/cmars/basen v0.0.0-20150613233007-fe3947df716e // indirect
	github.com/joeqian10/EasyLogger v1.0.0
	github.com/joeqian10/neo3-gogogo v1.1.2
	github.com/ontio/ontology-crypto v1.0.9
	github.com/polynetwork/poly v0.0.0-20210112063446-24e3d053e9d6
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114120411-3dcba035134f
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli v1.22.4
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	launchpad.net/gocheck v0.0.0-20140225173054-000000000087 // indirect
)

replace github.com/polynetwork/poly-go-sdk => github.com/zhiqiangxu/poly-go-sdk v0.0.0-20220118102343-71f305556b24

replace github.com/polynetwork/poly => github.com/zhiqiangxu/poly v0.0.0-20220118102005-aab67df86c20

replace github.com/tendermint/tm-db/064 => github.com/tendermint/tm-db v0.6.4