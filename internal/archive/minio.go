package archive

import (
	"context"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/lifecycle"
)

type Archive struct {
	Client *minio.Client
	Bucket string
}

type Object struct {
	Reader      io.ReadCloser
	Size        int64
	ContentType string
}

func (a *Archive) ApplyCDRRetention(ctx context.Context, days int) error {
	if days < 7 || days > 1095 {
		return fmt.Errorf("retention days must be between 7 and 1095")
	}
	config, err := a.Client.GetBucketLifecycle(ctx, a.Bucket)
	if err != nil {
		response := minio.ToErrorResponse(err)
		if response.Code != "NoSuchLifecycleConfiguration" {
			return fmt.Errorf("read bucket lifecycle: %w", err)
		}
		config = lifecycle.NewConfiguration()
	}
	return a.Client.SetBucketLifecycle(ctx, a.Bucket, cdrRetentionLifecycle(config, days))
}

func cdrRetentionLifecycle(config *lifecycle.Configuration, days int) *lifecycle.Configuration {
	const ruleID = "collector-raw-cdr-retention"
	rules := make([]lifecycle.Rule, 0, len(config.Rules)+1)
	for _, rule := range config.Rules {
		if rule.ID != ruleID {
			rules = append(rules, rule)
		}
	}
	rules = append(rules, lifecycle.Rule{
		ID:         ruleID,
		Status:     "Enabled",
		RuleFilter: lifecycle.Filter{Prefix: "cdr/"},
		Expiration: lifecycle.Expiration{Days: lifecycle.ExpirationDays(days)},
	})
	config.Rules = rules
	return config
}

func Open(ctx context.Context, endpoint, accessKey, secretKey, bucket string, useTLS bool) (*Archive, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useTLS,
	})
	if err != nil {
		return nil, err
	}
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
			return nil, err
		}
	}
	return &Archive{Client: client, Bucket: bucket}, nil
}

func (a *Archive) Put(ctx context.Context, key string, reader io.Reader, size int64, contentType string) error {
	_, err := a.Client.PutObject(ctx, a.Bucket, key, reader, size, minio.PutObjectOptions{
		ContentType:  contentType,
		UserMetadata: map[string]string{"immutable": "true"},
	})
	return err
}

func (a *Archive) OpenObject(ctx context.Context, key string) (Object, error) {
	info, err := a.Client.StatObject(ctx, a.Bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return Object{}, err
	}
	reader, err := a.Client.GetObject(ctx, a.Bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return Object{}, err
	}
	return Object{Reader: reader, Size: info.Size, ContentType: info.ContentType}, nil
}

func (a *Archive) DeletePrefix(ctx context.Context, prefix string) error {
	objects := a.Client.ListObjects(ctx, a.Bucket, minio.ListObjectsOptions{
		Prefix: prefix, Recursive: true,
	})
	for object := range objects {
		if object.Err != nil {
			return object.Err
		}
		if err := a.Client.RemoveObject(ctx, a.Bucket, object.Key, minio.RemoveObjectOptions{}); err != nil {
			return err
		}
	}
	for object := range a.Client.ListObjects(ctx, a.Bucket, minio.ListObjectsOptions{
		Prefix: prefix, Recursive: true,
	}) {
		if object.Err != nil {
			return object.Err
		}
		return fmt.Errorf("object %q still exists after prefix purge", object.Key)
	}
	return nil
}
