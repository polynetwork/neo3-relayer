package db

// db not used
import (
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

func (w *BoltDB) PutNeoRetry(k []byte) error {
	w.rwLock.Lock()
	defer w.rwLock.Unlock()

	return w.db.Update(func(btx *bolt.Tx) error {
		bucket := btx.Bucket(BKTNeoRetry)
		err := bucket.Put(k, []byte{0x00})
		if err != nil {
			return err
		}

		return nil
	})
}

func (w *BoltDB) DeleteNeoRetry(k []byte) error {
	w.rwLock.Lock()
	defer w.rwLock.Unlock()

	return w.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BKTNeoRetry)
		err := bucket.Delete(k)
		if err != nil {
			return err
		}
		return nil
	})
}

func (w *BoltDB) GetAllNeoRetry() ([][]byte, error) {
	w.rwLock.Lock()
	defer w.rwLock.Unlock()

	retryList := make([][]byte, 0)
	err := w.db.Update(func(tx *bolt.Tx) error {
		bw := tx.Bucket(BKTNeoRetry)
		err := bw.ForEach(func(k, _ []byte) error {
			_k := make([]byte, len(k))
			copy(_k, k)
			retryList = append(retryList, _k)
			if len(retryList) >= MAX_NUM {
				return fmt.Errorf("max num")
			}
			return nil
		})
		if err != nil {
			Log.Errorf("GetAllRetry err: %s", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return retryList, nil
}

func (w *BoltDB) Close() {
	w.rwLock.Lock()
	w.db.Close()
	w.rwLock.Unlock()
}
