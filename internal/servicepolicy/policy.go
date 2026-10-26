package servicepolicy

import (
	"errors"
	"fmt"
	"io"
	"os"

	fastls "github.com/FastTLS/fastls"
)

// Load is called once before listening. The file is trusted operator input;
// request DTOs never select it. Empty path keeps the exact existing client.
func Load(client fastls.Fastls, path string) (fastls.Fastls, error) {
	if path == "" {
		return client, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return client, fmt.Errorf("read address policy file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return client, errors.New("cannot read address policy file")
	}
	if len(data) > 1<<20 {
		return client, errors.New("address policy file exceeds 1 MiB")
	}
	return configure(client, data)
}

func configure(client any, data []byte) (fastls.Fastls, error) {
	compiler, ok := client.(interface {
		WithAddressPolicyJSON([]byte) (fastls.Fastls, error)
	})
	if !ok {
		return fastls.Fastls{}, errors.New("address policy requires a policy-capable fastls core; refusing to start")
	}
	return compiler.WithAddressPolicyJSON(data)
}
