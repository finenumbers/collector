package archive

import (
	"context"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Archive struct {
	Client *minio.Client
	Bucket string
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
