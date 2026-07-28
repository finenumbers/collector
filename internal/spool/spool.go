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
	blockedSourcesName     = []byte("blocked_sources")
)

type Queue struct {
	db *bolt.DB
}

type Item struct {
	Key  []byte
	Data []byte
}

type Entry struct {
	ReceivedAt time.Time
	EventID    string
	Payload    []byte
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
		for _, name := range [][]byte{
			bucketName, quarantineBucketName, quarantineMetadataName, blockedSourcesName,
		} {
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

func (q *Queue) EnqueueBatchWithSourceFence(
	entries []Entry, sourceIP func([]byte) string,
) (uint64, error) {
	var accepted uint64
	err := q.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		blocked := tx.Bucket(blockedSourcesName)
		for _, entry := range entries {
			source := sourceIP(entry.Payload)
			if source != "" && blocked.Get([]byte(source)) != nil {
				continue
			}
			key := []byte(fmt.Sprintf("%020d/%s", entry.ReceivedAt.UnixNano(), entry.EventID))
			if err := bucket.Put(key, entry.Payload); err != nil {
				return err
			}
			accepted++
		}
		return nil
	})
	return accepted, err
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

func (q *Queue) EnqueueBatch(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	return q.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		for _, entry := range entries {
			key := []byte(fmt.Sprintf("%020d/%s", entry.ReceivedAt.UnixNano(), entry.EventID))
			if err := bucket.Put(key, entry.Payload); err != nil {
				return err
			}
		}
		return nil
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

func (q *Queue) DeleteMatching(match func([]byte) bool) (uint64, error) {
	if match == nil {
		return 0, nil
	}
	var deleted uint64
	err := q.db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketName, quarantineBucketName} {
			bucket := tx.Bucket(name)
			cursor := bucket.Cursor()
			for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
				if !match(value) {
					continue
				}
				if err := cursor.Delete(); err != nil {
					return err
				}
				_ = tx.Bucket(quarantineMetadataName).Delete(key)
				deleted++
			}
		}
		return nil
	})
	return deleted, err
}

func (q *Queue) BlockSourceAndDelete(source string, match func([]byte) bool) (uint64, error) {
	var deleted uint64
	err := q.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(blockedSourcesName).Put([]byte(source), []byte{1}); err != nil {
			return err
		}
		for _, name := range [][]byte{bucketName, quarantineBucketName} {
			bucket := tx.Bucket(name)
			cursor := bucket.Cursor()
			for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
				if !match(value) {
					continue
				}
				if err := cursor.Delete(); err != nil {
					return err
				}
				_ = tx.Bucket(quarantineMetadataName).Delete(key)
				deleted++
			}
		}
		return nil
	})
	return deleted, err
}

func (q *Queue) UnblockSource(source string) error {
	return q.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(blockedSourcesName).Delete([]byte(source))
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
