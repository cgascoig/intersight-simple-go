package client

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/go-fed/httpsig"
)

type Config struct {
	KeyID   string
	KeyFile string
	KeyData string
	Host    string
}

type Client struct {
	keyID      string
	key        crypto.PrivateKey
	host       string
	httpClient *http.Client
}

func NewClient(config Config) (*Client, error) {
	client := &Client{
		httpClient: &http.Client{
			// TODO: make logging an option
			// Transport: &loggingRoundTripper{},
		},
	}

	if config.Host == "" {
		client.host = "intersight.com"
	} else {
		client.host = config.Host
	}

	if config.KeyID == "" {
		return nil, fmt.Errorf("KeyID must be set")
	} else {
		client.keyID = config.KeyID
	}

	if config.KeyFile != "" && config.KeyData != "" {
		return nil, fmt.Errorf("Both KeyFile and KeyData cannot be set")
	}

	if config.KeyFile != "" {
		key, err := loadKeyFromFile(config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("Error loading key from file: %v", err)
		}
		client.key = key
	}

	if config.KeyData != "" {
		key, err := loadKeyFromString(config.KeyData)
		if err != nil {
			return nil, fmt.Errorf("Error loading key from string: %v", err)
		}
		client.key = key
	}

	return client, nil
}

func (c *Client) sign(r *http.Request, body []byte) error {
	prefs := []httpsig.Algorithm{httpsig.RSA_SHA256}
	digestAlgorithm := httpsig.DigestSha256
	headersToSign := []string{httpsig.RequestTarget, "host", "date", "digest"}

	signer, _, err := httpsig.NewSigner(prefs, digestAlgorithm, headersToSign, httpsig.Authorization, 0)
	if err != nil {
		return err
	}

	// If r were a http.ResponseWriter, call SignResponse instead.
	return signer.SignRequest(c.key, c.keyID, r, body)
}

func (c *Client) Get(query string) (interface{}, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s%s", c.host, query), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %v", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Host", c.host)
	req.Host = c.host
	req.Header.Add("Date", time.Now().UTC().Format(http.TimeFormat))

	err = c.sign(req, []byte{})
	if err != nil {
		return nil, fmt.Errorf("signing error: %v", err)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request sending error: %v", err)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		errbody, err2 := ioutil.ReadAll(res.Body)
		if err2 == nil {
			return nil, fmt.Errorf("request failed: %v: %s", res.Status, string(errbody))
		} else {
			return nil, fmt.Errorf("request failed: %v", res.Status)
		}
	}

	var ret interface{}
	err = json.NewDecoder(res.Body).Decode(&ret)
	if err != nil {
		return nil, fmt.Errorf("JSON parsing error: %v", err)
	}

	return ret, nil
}

type loggingRoundTripper struct {
}

func (rt *loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Printf("HTTP Req: %+v\n", req)
	res, err := http.DefaultTransport.RoundTrip(req)
	fmt.Printf("HTTP Res: %+v\n", res)
	fmt.Printf("HTTP Err: %v\n", err)
	return res, err
}
