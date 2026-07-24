package archive

import (
	"context"
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
