package spool

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketName             = []byte("syslog")
	quarantineBucketName   = []byte("syslog_quarantine")
	quarantineMetadataName = []byte("syslog_quarantine_metadata")
)

type Queue struct {
	db *bolt.DB
}

type Item struct {
	Key  []byte
	Data []byte
}

func Open(path string) (*Queue, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{
		Timeout:        5 * time.Second,
		NoFreelistSync: true,
	})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketName, quarantineBucketName, quarantineMetadataName} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &Queue{db: db}, nil
}

func (q *Queue) Quarantine(key, payload []byte, reason string) error {
	return q.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(quarantineBucketName).Put(key, payload); err != nil {
			return err
		}
		if err := tx.Bucket(quarantineMetadataName).Put(key, []byte(reason)); err != nil {
			return err
		}
		return tx.Bucket(bucketName).Delete(key)
	})
}

func (q *Queue) Close() error {
	return q.db.Close()
}

func (q *Queue) Enqueue(receivedAt time.Time, eventID string, payload []byte) error {
	key := []byte(fmt.Sprintf("%020d/%s", receivedAt.UnixNano(), eventID))
	return q.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Put(key, payload)
	})
}

func (q *Queue) Peek(limit int) ([]Item, error) {
	items := make([]Item, 0, limit)
	err := q.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(bucketName).Cursor()
		for key, value := cursor.First(); key != nil && len(items) < limit; key, value = cursor.Next() {
			items = append(items, Item{Key: bytes.Clone(key), Data: bytes.Clone(value)})
		}
		return nil
	})
	return items, err
}

func (q *Queue) Delete(keys [][]byte) error {
	if len(keys) == 0 {
		return nil
	}
	return q.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		for _, key := range keys {
			if err := bucket.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}

func (q *Queue) Depth() (uint64, error) {
	var depth uint64
	err := q.db.View(func(tx *bolt.Tx) error {
		depth = uint64(tx.Bucket(bucketName).Stats().KeyN)
		return nil
	})
	return depth, err
}

func (q *Queue) QuarantineDepth() (uint64, error) {
	var depth uint64
	err := q.db.View(func(tx *bolt.Tx) error {
		depth = uint64(tx.Bucket(quarantineBucketName).Stats().KeyN)
		return nil
	})
	return depth, err
}
