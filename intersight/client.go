package intersight

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-fed/httpsig"
)

type Logger interface {
	Printf(format string, v ...any)
}

type Config struct {
	KeyID   string
	KeyFile string
	KeyData string
	Host    string
	Logger  Logger
}

type Client struct {
	keyID   string
	keyData []byte
	host    string
	client  *http.Client
}

var signedHeaders = []string{httpsig.RequestTarget, "date", "host", "content-type", "digest"}

func NewClient(configs ...Config) (*Client, error) {
	client := &Client{}
	var config Config

	if len(configs) == 1 {
		config = configs[0]
	}

	if len(configs) > 1 {
		return nil, fmt.Errorf("only 1 config parameter is supported")
	}

	//Apply defaults

	if config.Host == "" {
		config.Host = "intersight.com"
	}

	if config.KeyID == "" {
		envKeyId := os.Getenv("IS_KEYID")
		if envKeyId != "" {
			config.KeyID = envKeyId
		}
	}

	if config.KeyFile == "" {
		envKeyFile := os.Getenv("IS_KEYFILE")
		if envKeyFile != "" {
			config.KeyFile = envKeyFile
		}
	}

	//Create client from config
	client.host = config.Host

	if config.KeyID == "" {
		return nil, fmt.Errorf("KeyID must be set")
	} else {
		client.keyID = config.KeyID
	}

	if config.KeyFile != "" && config.KeyData != "" {
		return nil, fmt.Errorf("both KeyFile and KeyData cannot be set")
	}

	if config.KeyFile != "" {
		keyData, err := os.ReadFile(config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("error loading key from file: %v", err)
		}
		client.keyData = keyData
	}

	if config.KeyData != "" {
		client.keyData = []byte(config.KeyData)
	}

	var baseTransport = http.DefaultTransport

	var transport http.RoundTripper
	decodedKeyData, _ := pem.Decode(client.keyData)
	if decodedKeyData == nil {
		return nil, fmt.Errorf("invalid key - unable to decode PEM data")
	}
	if decodedKeyData.Type == "RSA PRIVATE KEY" {
		k, err := x509.ParsePKCS1PrivateKey(decodedKeyData.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse key data as PKCS1 private key: %v", err)
		}

		signer, _, err := httpsig.NewSigner(
			[]httpsig.Algorithm{httpsig.RSA_SHA256},
			httpsig.DigestSha256,
			signedHeaders,
			httpsig.Authorization,
			0,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create RSA_SHA256 signer: %v", err)
		}
		transport = newSignTransport(baseTransport, signer, client.keyID, k, config.Logger)
	} else {
		key, err := x509.ParsePKCS8PrivateKey(decodedKeyData.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse key data as PKCS8 private key: %v", err)
		}
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			signer, _, err := httpsig.NewSigner(
				[]httpsig.Algorithm{httpsig.ECDSA_SHA256},
				httpsig.DigestSha256,
				signedHeaders,
				httpsig.Authorization,
				0,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to create ECDSA_SHA256 signer: %v", err)
			}
			transport = newSignTransport(baseTransport, signer, client.keyID, k, config.Logger)
		default:
			return nil, fmt.Errorf("key is in PKCS8 format but not ECDSA (v3)")
		}
	}

	client.client = &http.Client{
		Transport: transport,
	}

	return client, nil
}

func (c *Client) Get(path string) (any, error) {
	return c.Call(http.MethodGet, path, []byte(""))
}

func (c *Client) Post(path string, body []byte) (any, error) {
	return c.Call(http.MethodPost, path, body)
}

func (c *Client) Patch(path string, body []byte) (any, error) {
	return c.Call(http.MethodPatch, path, body)
}

func (c *Client) Delete(path string) (any, error) {
	return c.Call(http.MethodDelete, path, []byte(""))
}

func (c *Client) Call(method, path string, body []byte) (any, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("https://%s%s", c.host, path), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("unable to create Intersight request: %v", err)
	}
	req.Header.Set("Host", c.host)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to send Intersight request: %v", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("request failed: %d %s", res.StatusCode, res.Status)
	}

	var ret any
	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read Intersight response body: %v", err)
	}
	if len(resBytes) == 0 {
		return nil, nil
	}
	err = json.Unmarshal(resBytes, &ret)
	if err != nil {
		return nil, fmt.Errorf("unable to parse Intersight response: %v", err)
	}
	return ret, nil
}

type signTransport struct {
	wrappedTransport http.RoundTripper
	signer           httpsig.Signer
	keyId            string
	key              crypto.PrivateKey
	log              Logger
}

func newSignTransport(transport http.RoundTripper, signer httpsig.Signer, keyId string, key crypto.PrivateKey, log Logger) http.RoundTripper {
	return &signTransport{
		wrappedTransport: transport,
		signer:           signer,
		keyId:            keyId,
		key:              key,
	}
}

func (t *signTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Date") == "" {
		req.Header.Set("Date", time.Now().In(time.UTC).Format(time.RFC1123))
	}
	b := &bytes.Buffer{}
	if req.Body != nil {
		n, err := b.ReadFrom(req.Body)
		if err != nil {
			return nil, err
		}

		defer req.Body.Close()

		if n != 0 {
			req.Body = io.NopCloser(bytes.NewReader(b.Bytes()))
		}
	}
	err := t.signer.SignRequest(t.key, t.keyId, req, b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("signing request: %v", err)
	}

	if t.log != nil {
		t.log.Printf("signTransport: req: %v", req)
		t.log.Printf("signTransport: body: %v", b.String())
	}
	res, err := t.wrappedTransport.RoundTrip(req)
	if t.log != nil {
		t.log.Printf("signTransport: res: %v", res)
		t.log.Printf("signTransport: err: %v", err)
	}
	return res, err
}
