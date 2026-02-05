package intersight

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	// this is not a real/valid key
	v2_secret_key = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvV0n1s8QcR7S7u5rR94//VoUSIxJ7jvLdZRNYRQcQCECxp+H
V6ut+61D5t7YQqNcTIEv71ssC9UNs/wCIFELeN5MweLqvYto03SFJB0bLZ+ycpnp
e9jTqALZqa6uCLycFjtV9s7sW5nZZcuDiyLlNCygtkzXkUdBQ3ycaZpJphKwezQ1
xXgmWaUV6JqihSwVgj9U7sZOQN/6eCbbL2/kLoHnAYVIlbiuV0uTZsFGLsm2ZP1o
A3h2NdqhPHrBlWSmUAdhYIGlu7WNQ0yN5d6PpwHERCUI2+fOKxau8C42EYDttYf1
tnU4VZC7ItmE8ZDlrGn9f5F8virhhlBEESTXkwIDAQABAoIBABfQiVwYembfi4OE
9HT7XGzOUVK2Ye3WE0ZcOkcFMnBWNnUoRusdqinGpo14ZRYsWUU90ft2KdnrF2gV
P2c1Cg5PVrPjh8YCrFI7iyr5hht8xAJpnNV4dVXh1eHjF/v9TFv3Zl49s7fpZ0/I
AmkTIGQpYKTMkSeyIGEOYNVfE/gQljcRz6yf60GmWJY5IglXh/00GtB3GQHJqWLs
rWMi7uwtFCp6dpQDjC7VAanAnmkti4/+hiNC8c+29Zf5LcQYPz2oY3V1UlpynyYH
b+mRL5iFJwcKZs+93waTyD/igFzK+ly9Nw3/vM/D0h5wxw8UPMFHyBKN3MAI4tzW
M1QtbYECgYEA5c3V1mReeOIDx6ilUebKUooryhg0EcKIYA5bUFvlYkB7E688CpdL
nCHoeRjCKcQ0jZzpZcBpB+CoaHNLCvpaKSHzvXGmFUztMX7FMVGERWk8RwvxCVl3
j9LstVvcXklt6OE2E3GLQUhLFbs0xWghlNZWMf/KCx7t/WUChRgGRWECgYEA0vMx
EDlLISZTheR2hKlENn2yAxYfo8XieArPcjt1kivGVVqnItUMtzCRHnF1cjYnbk8g
Tf5x+8LwlOHTCX9VrQQYM98t0WsWVSmkrzss1/K0yu09sYsdOet9UL7Jet7kpA3L
dfRxXQHySJaUPVYFR9f8hQsuJrUdndFiHdHlzXMCgYEAzFNzIXgGo9bZ44mozKS3
GiKugrd4fJ4KIdZCDLZYwz5v8HWrngMeAEoJ6LpB0V8aFxwATi+Bc7amJpD0lWM6
DT6Z+MR3FpNahtqfvJUtVYYXSVhtzZFWBHRXcX2m99K0Pg8YxLr9RWNhF4Znimpn
CW52H2i+nZq3oslQL0TINqECgYA33LTScgmmNqsJmu2TxetNbs3UKWipiv6lAV/c
BUjmM3drJP17qOWcIV1crXkHjLW2bXfFj6sJm57wHjkvm6vJjHsISYKtoWkhlkyJ
JueCLECaOGcM/CT6MJVX654ZTqtHkmudyeS3V4uck1ugPoZZdyXk6YgIMhAsucT8
1pe/ZwKBgGoZAhOaR/s5EM/bwIpqPE870VnWeIbvDc8vMH3tW/q7SysfyNxyZ99w
pQ8EfDaxnEFVuY7Xa8i/qr7mmXo5E+d0TrxkB1bqtwaJJ8ojaW5G/PIkU3aTC6uV
11QYh2F1qu2ow8Y4Q3DZ78jc9M3gHvzuknyencU2K0+VhVgwEVtI
-----END RSA PRIVATE KEY-----`
	v2_key_id = "59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b3ba347564612d3198f5b1"

	// this is not a real/valid key
	v3_secret_key = `
-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFpLumf8DcLaJSAM1
pp6rmKCz00eZAewOElJKETFiW/WhRANCAAT0RlNvtEUFP2n6Aq38dnWvsT1AkZjm
B9I2RZyK1NILUMKp1rdSI05SaOS5Ca5YyJ4ZVOfSIN0ZduOSAkWaAPy0
-----END EC PRIVATE KEY-----
`
	v3_key_id = "59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b39fc27564612d319801ce"
)

func TestNewClient(t *testing.T) {
	var client *Client
	var err error

	// test v2 key
	client, err = NewClient(Config{
		KeyID:   v2_key_id,
		KeyData: v2_secret_key,
	})
	assert.NoError(t, err)

	assert.NotNil(t, client)

	// test v3 key
	client, err = NewClient(Config{
		KeyID:   v3_key_id,
		KeyData: v3_secret_key,
	})
	assert.NoError(t, err)

	assert.NotNil(t, client)

	// test invalid key
	client, err = NewClient(Config{
		KeyID:   "",
		KeyData: "djskfeoi",
	})
	assert.Error(t, err)

	assert.Nil(t, client)

	// test OAuth2
	client, err = NewClient(Config{
		ClientID:     "123",
		ClientSecret: "djskfeoi",
	})
	assert.NoError(t, err)

	assert.NotNil(t, client)
}

type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestV2SigningGet(t *testing.T) {
	const (
		date        = "Thu, 23 Jun 2022 00:57:07 GMT"
		contentType = "application/json"
		host        = "intersight.com"
	)
	client, err := NewClient(Config{
		KeyID:   v2_key_id,
		KeyData: v2_secret_key,
		BaseTransport: RoundTripFunc(func(req *http.Request) *http.Response {
			assert.Equal(t, "SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", req.Header.Get("Digest"), "Digest")
			assert.Equal(t, `Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b3ba347564612d3198f5b1",algorithm="hs2019",headers="(request-target) date host content-type digest",signature="Ioygtr7Uq8dHJirKU0Hq/LLQYGeLHnzgZwaSpsw1yMqkrlx3Atnu7LBISrQ+wO2QkQbvp85VqKawnikuoXoCJVaLb1KtKOMERWUPEbnPgzS/gORWWpPlMXLHbNALdInuvSSogh1qXysKHJtnu2srWmOFqU3g2aZ5gfkrzeQ/eQ97okPzpq8s8N0oUO4FmnXXSSS7MGp/yUbq+7LZkXYPIO0sapPZqSKIAtpfmoU5s218sdoxW2TMAK+pnmux1K4idQVCbz5BX3Yyb2iXR55usH1qk3IUSACeZJ+X7gP8CKYTUTEnkkCQa/TLbtD/hcjrRyqD6K7RXf59ZiimQP5FHA=="`, req.Header.Get("Authorization"), "Authorization")
			assert.Equal(t, host, req.Header.Get("Host"), "Host")
			assert.Equal(t, contentType, req.Header.Get("Content-Type"), "Content-Type")
			assert.Equal(t, date, req.Header.Get("Date"), "Date")

			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "OK",
				Body:       io.NopCloser(strings.NewReader(`{}`)),
			}
		}),
	})

	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "https://intersight.com/api/v1/ntp/Policies", bytes.NewReader([]byte("")))
	assert.NoError(t, err)
	req.Header.Set("Host", host)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Date", date)
	res, err := client.client.Do(req)
	assert.NoError(t, err)
	assert.NotNil(t, res)
}

func TestV2SigningPatch(t *testing.T) {
	const (
		body        = `{"Enabled": false}`
		date        = "Thu, 23 Jun 2022 00:59:53 GMT"
		contentType = "application/json"
		host        = "intersight.com"
	)

	client, err := NewClient(Config{
		KeyID:   v2_key_id,
		KeyData: v2_secret_key,
		BaseTransport: RoundTripFunc(func(req *http.Request) *http.Response {
			assert.Equal(t, "SHA-256=Bzjzvy6urg1NJwfPKkZD1hRAMnyZdcKg9HLATHU/ULc=", req.Header.Get("Digest"), "Digest")
			assert.Equal(t, `Signature keyId="59c84e4a16267c0001c23428/59cc595416267c0001a0dfc7/62b3ba347564612d3198f5b1",algorithm="hs2019",headers="(request-target) date host content-type digest",signature="S/hT9RE5Wrxxem1RJyuO6futrop9iTfO48u8agLwd+42LCLvgu4wMQgs4pionxKwpChnozM87OF0cMnqKzYeW8X/0bp+/ZHmF47CBuP71Y/tn09bCZvwJ3yf0KJ2IHT1sFF9eZDN7ezX2ZpiVWadtvBWJlLBvqlENhKqNcJK+Nu0UprBJOoUDcPIjb6kJxUL+Lhn8LSga6fWqPyG0X+FweIl8RnQSDzulvzc82gbOPCAg/mFzui9aZ4bySXmgACo7DNBsfw6OgMldVE+8R49YEruLzRXvroMHanxzG9hf+BaDZ5kheDRs4NlZgLu/INwukGGMp//MhsaI6cOuuNs/A=="`, req.Header.Get("Authorization"), "Authorization")
			assert.Equal(t, host, req.Header.Get("Host"), "Host")
			assert.Equal(t, contentType, req.Header.Get("Content-Type"), "Content-Type")
			assert.Equal(t, date, req.Header.Get("Date"), "Date")
			reqBody, _ := io.ReadAll(req.Body)
			assert.Equal(t, []byte(body), reqBody)

			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "OK",
				Body:       io.NopCloser(strings.NewReader("{}")),
			}
		}),
	})

	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPatch, "https://intersight.com/api/v1/ntp/Policies/629713736275722d31a1ac7c", bytes.NewReader([]byte(body)))
	assert.NoError(t, err)
	req.Header.Set("Host", host)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Date", date)
	res, err := client.client.Do(req)
	assert.NoError(t, err)
	assert.NotNil(t, res)
}

func TestGet(t *testing.T) {
	client, err := NewClient(Config{
		KeyID:   v2_key_id,
		KeyData: v2_secret_key,
		BaseTransport: RoundTripFunc(func(req *http.Request) *http.Response {

			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "OK",
				Body:       io.NopCloser(strings.NewReader(`{"aa": "AA", "bb": "BB"}`)),
			}
		}),
	})

	assert.NoError(t, err)

	res, err := client.Get("/api/v1/ntp/Policies")
	assert.NoError(t, err)
	assert.Equal(t, map[string]any{
		"aa": "AA",
		"bb": "BB",
	}, res)
}

func TestErrorResponse(t *testing.T) {
	client, err := NewClient(Config{
		KeyID:   v2_key_id,
		KeyData: v2_secret_key,
		BaseTransport: RoundTripFunc(func(req *http.Request) *http.Response {

			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Status:     "400 Bad Request",
				Body:       io.NopCloser(strings.NewReader(`{"code":"InvalidRequest","message":"Cannot set the property 'policy.AbstractPolicy.Name'. The property cannot be empty.","messageId":"barcelona_request_cannot_access_property_required","messageParams":{"1":"policy.AbstractPolicy","2":"Name"},"traceId":"STD4v5iGb_OWgyZoHSN7WdY6iSAa2lBfnScGBWhYvOr8bnZw7y_iQQ=="}`)),
			}
		}),
	})

	assert.NoError(t, err)

	res, err := client.Get("/api/v1/ntp/Policies")
	assert.Error(t, err)
	assert.Equal(t, fmt.Errorf("request failed: 400 Bad Request: Cannot set the property 'policy.AbstractPolicy.Name'. The property cannot be empty."), err)
	assert.Nil(t, res)
}

func TestOAuth2(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/iam/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token":"mock_token","token_type":"Bearer","expires_in":3600}`))
		} else if r.URL.Path == "/api/v1/ntp/Policies" {
			assert.Equal(t, "Bearer mock_token", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"aa": "AA", "bb": "BB"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	oldTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()

	host := strings.TrimPrefix(server.URL, "https://")
	client, err := NewClient(Config{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		Host:         host,
		TokenURL:     server.URL + "/iam/token",
	})

	assert.NoError(t, err)

	res, err := client.Get("/api/v1/ntp/Policies")
	assert.NoError(t, err)
	assert.Equal(t, map[string]any{
		"aa": "AA",
		"bb": "BB",
	}, res)
}

type MockLogger struct {
	Captured []string
}

func (l *MockLogger) Printf(format string, v ...any) {
	l.Captured = append(l.Captured, fmt.Sprintf(format, v...))
}

func TestOAuth2Logging(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/iam/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token":"mock_token","token_type":"Bearer","expires_in":3600}`))
		} else if r.URL.Path == "/api/v1/log-test" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	mockLog := &MockLogger{}
	host := strings.TrimPrefix(server.URL, "https://")

	// Use a custom transport to avoid certificate errors with the test server
	// and to ensure we can control the base transport if needed.
	// NewClient will wrap this with loggingTransport.
	baseTransport := server.Client().Transport

	client, err := NewClient(Config{
		ClientID:      "test_client_id",
		ClientSecret:  "test_client_secret",
		Host:          host,
		TokenURL:      server.URL + "/iam/token",
		Logger:        mockLog,
		BaseTransport: baseTransport,
	})

	assert.NoError(t, err)

	_, err = client.Get("/api/v1/log-test")
	assert.NoError(t, err)

	// Verify logs were captured
	// We expect logs for the request and response of the API call.
	// We might also see logs for the token fetch if that uses the same transport stack (which it should now)

	assert.NotEmpty(t, mockLog.Captured, "Expected logs to be captured")

	foundReq := false
	foundRes := false
	for _, logMsg := range mockLog.Captured {
		if strings.Contains(logMsg, "req:") {
			foundReq = true
		}
		if strings.Contains(logMsg, "res:") {
			foundRes = true
		}
	}
	assert.True(t, foundReq, "Expected request log")
	assert.True(t, foundRes, "Expected response log")
}
