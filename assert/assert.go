package assert

import (
	"bytes"
	"encoding/json"
	"testing"

	"text/template"

	"github.com/cgascoig/intersight-simple-go/client"
	"github.com/stretchr/testify/assert"
)

// TestingT is an interface wrapper around *testing.T
type TestingT interface {
	Errorf(format string, args ...interface{})
}

// match recursively compares `expected` to `got`.
// If there are extra map elements in `got` they are ignored.
// Only types relevant for JSON decoded objects are supported
func match(t TestingT, expected, got interface{}) bool {

	if expected == nil && got == nil {
		return true
	}

	switch e := expected.(type) {
	case string:
		if g, ok := got.(string); ok {
			if e == g {
				return true
			} else {
				t.Errorf("got '%s', expected '%s'", g, e)
				return false
			}
		}
		t.Errorf("mismatched types")
		return false

	case float64:
		if g, ok := got.(float64); ok {
			if e == g {
				return true
			} else {
				t.Errorf("got '%f', expected '%f'", g, e)
				return false
			}
		}
		return false
	case bool:
		if g, ok := got.(bool); ok {
			if e == g {
				return true
			} else {
				t.Errorf("got '%t', expected '%t'", g, e)
				return false
			}
		}
		t.Errorf("mismatched types")
		return false
	case []interface{}:
		if g, ok := got.([]interface{}); ok {
			if len(e) != len(g) {
				t.Errorf("slice lengths unequal (expected %d, got %d)", len(e), len(g))
				return false
			}
			for i := range e {
				if !match(t, e[i], g[i]) {
					return false
				}
			}
			return true
		}
		t.Errorf("mismatched types")
		return false
	case map[string]interface{}:
		if g, ok := got.(map[string]interface{}); ok {
			for k := range e {
				if _, ok := g[k]; !ok {
					t.Errorf("expected key %s missing", k)
					return false
				}
				if !match(t, e[k], g[k]) {
					return false
				}
			}
			return true
		}
		t.Errorf("mismatched types")
		return false
	}
	t.Errorf("unsupported type: %T", expected)
	return false
}

func AssertMOComply(t *testing.T, apiQuery string, expectedJSONTemplate string, templateVars interface{}, config ...client.Config) {
	tmpl, err := template.New("expectedJSON").Parse(expectedJSONTemplate)
	if err != nil {
		t.Errorf("Unable to parse expected JSON template: %v", err)
		return
	}
	var expectedJSON bytes.Buffer
	err = tmpl.Execute(&expectedJSON, templateVars)
	if err != nil {
		t.Errorf("Unable to execute expected JSON template: %v", err)
		return
	}

	var expected interface{}
	err = json.Unmarshal(expectedJSON.Bytes(), &expected)
	if err != nil {
		t.Errorf("expectedJSON can't be unmarshalled: %v", err)
		return
	}

	c, err := client.NewClient(config...)
	assert.NoError(t, err, "error setting up Intersight client")
	assert.NotNil(t, c, "error setting up Intersight client")

	res, err := c.Get(apiQuery)
	assert.NoError(t, err, "Intersight API request error")
	assert.NotNil(t, res, "Intersight API request error")

	// Our match is less strict than assert.Equal, but if our match() finds a difference, use assert.Equal to raise the error with a nice diff
	if !match(&noopT{}, expected, res) {
		assert.Equal(t, expected, res, "Intersight MO does not match expected, showing full diff")
	}
}

type noopT struct{}

func (t *noopT) Errorf(format string, args ...interface{}) {

}
