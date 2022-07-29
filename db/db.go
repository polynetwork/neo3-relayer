package db

// db not used
import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/boltdb/bolt"
	//"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/polynetwork/neo3-relayer/log"
	"path"
	"strings"
	"sync"
)

var Log = log.Log

const MAX_NUM = 1000

var (
	BKTNeoCheck = []byte("NeoCheck")
	BKTNeoRetry = []byte("NeoRetry")

	BKTHeight = []byte("Height")
	NeoHeightKey  = []byte("Neo")
	ZionHeightKey = []byte("Zion")
)

type BoltDB struct {
	rwLock   *sync.RWMutex
	db       *bolt.DB
	filePath string
}

func NewBoltDB(filePath string) (*BoltDB, error) {
	if !strings.Contains(filePath, ".bin") {
		filePath = path.Join(filePath, "bolt.bin")
	}
	w := new(BoltDB)
	db, err := bolt.Open(filePath, 0644, &bolt.Options{InitialMmapSize: 500000})
	if err != nil {
		return nil, err
	}
	w.db = db
	w.rwLock = new(sync.RWMutex)
	w.filePath = filePath

	// neo check
	if err = db.Update(func(btx *bolt.Tx) error {
		_, err := btx.CreateBucketIfNotExists(BKTNeoCheck)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	// neo retry
	if err = db.Update(func(btx *bolt.Tx) error {
		_, err := btx.CreateBucketIfNotExists(BKTNeoRetry)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	// height
	if err = db.Update(func(btx *bolt.Tx) error {
		_, err := btx.CreateBucketIfNotExists(BKTHeight)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *BoltDB) PutNeoCheck(neoTxHash string, v []byte) error {
	w.rwLock.Lock()
	defer w.rwLock.Unlock()

	k, err := hex.DecodeString(neoTxHash)
	if err != nil {
		return err
	}
	return w.db.Update(func(btx *bolt.Tx) error {
		bucket := btx.Bucket(BKTNeoCheck)
		err := bucket.Put(k, v)
		if err != nil {
			return err
		}

		return nil
	})
}

func (w *BoltDB) DeleteNeoCheck(neoTxHash string) error {
	w.rwLock.Lock()
	defer w.rwLock.Unlock()

	k, err := hex.DecodeString(neoTxHash)
	if err != nil {
		return err
	}
	return w.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BKTNeoCheck)
		err := bucket.Delete(k)
		if err != nil {
			return err
		}
		return nil
	})
}

func (w *BoltDB) GetNeoAllCheck() (map[string][]byte, error) {
	w.rwLock.Lock()
	defer w.rwLock.Unlock()

	checkMap := make(map[string][]byte)
	err := w.db.Update(func(tx *bolt.Tx) error {
		bw := tx.Bucket(BKTNeoCheck)
		err := bw.ForEach(func(k, v []byte) error {
			_k := make([]byte, len(k))
			_v := make([]byte, len(v))
			copy(_k, k)
			copy(_v, v)
			checkMap[hex.EncodeToString(_k)] = _v
			if len(checkMap) >= MAX_NUM {
				return fmt.Errorf("max num")
			}
			return nil
		})
		if err != nil {
			Log.Errorf("GetAllCheck err: %s", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return checkMap, nil
}

func (w *BoltDB) PutNeoHeight(height uint64) error {
	w.rwLock.Lock()
	defer w.rwLock.Unlock()

	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, height)
	return w.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BKTHeight)
		err := bucket.Put(NeoHeightKey, raw)
		if err != nil {
			return err
		}

		return nil
	})
}

func (w *BoltDB) GetNeoHeight() uint64 {
	w.rwLock.RLock()
	defer w.rwLock.RUnlock()

	var height uint64
	_ = w.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BKTHeight)
		raw := bucket.Get(NeoHeightKey)
		if len(raw) == 0 {
			height = 0
			return nil
		}
		height = binary.LittleEndian.Uint64(raw)
		return nil
	})

	return height
}

func (w *BoltDB) PutZionHeight(height uint64) error {
	w.rwLock.Lock()
	defer w.rwLock.Unlock()

	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, height)
	return w.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BKTHeight)
		err := bucket.Put(ZionHeightKey, raw)
		if err != nil {
			return err
		}

		return nil
	})
}

func (w *BoltDB) GetZionHeight() uint64 {
	w.rwLock.RLock()
	defer w.rwLock.RUnlock()

	var height uint64
	_ = w.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BKTHeight)
		raw := bucket.Get(ZionHeightKey)
		if len(raw) == 0 {
			height = 0
			return nil
		}
		height = binary.LittleEndian.Uint64(raw)
		return nil
	})

	return height
}

func (w *BoltDB) Close() {
	w.rwLock.Lock()
	w.db.Close()
	w.rwLock.Unlock()
}
