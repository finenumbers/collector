package ftp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Provisioner struct {
	BaseURL  string
	Username string
	Password string
	Client   *http.Client
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

func NewProvisioner(baseURL, username, password string) *Provisioner {
	return &Provisioner{
		BaseURL: strings.TrimRight(baseURL, "/"), Username: username, Password: password,
		Client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (p *Provisioner) CreateUser(ctx context.Context, username, password, home string) error {
	token, err := p.token(ctx)
	if err != nil {
		return err
	}
	body := map[string]any{
		"status": 1, "username": username, "password": password, "home_dir": home,
		"permissions": map[string][]string{"/": {"*"}},
		"filesystem":  map[string]any{"provider": 0},
		"filters": map[string]any{
			"denied_protocols": []string{"SSH", "HTTP", "DAV"},
		},
	}
	return p.request(ctx, http.MethodPost, "/api/v2/users", token, body)
}

func (p *Provisioner) DeleteUser(ctx context.Context, username string) error {
	token, err := p.token(ctx)
	if err != nil {
		return err
	}
	return p.request(ctx, http.MethodDelete, "/api/v2/users/"+username, token, nil)
}

func (p *Provisioner) token(ctx context.Context) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.BaseURL+"/api/v2/token", nil)
	if err != nil {
		return "", err
	}
	request.SetBasicAuth(p.Username, p.Password)
	response, err := p.Client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return "", fmt.Errorf("SFTPGo token: %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	var token tokenResponse
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		return "", err
	}
	if token.AccessToken == "" {
		return "", fmt.Errorf("SFTPGo returned an empty access token")
	}
	return token.AccessToken, nil
}

func (p *Provisioner) request(ctx context.Context, method, path, token string, body any) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, p.BaseURL+path, payload)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := p.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		content, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("SFTPGo %s %s: %s: %s", method, path, response.Status, strings.TrimSpace(string(content)))
	}
	return nil
}
