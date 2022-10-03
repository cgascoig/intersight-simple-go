package assert

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name      string
		expected  interface{}
		got       interface{}
		ret       bool
		wantError int
	}{
		{
			name:      "strings equal",
			expected:  "123",
			got:       "123",
			ret:       true,
			wantError: 0,
		},
		{
			name:      "strings unequal",
			expected:  "123",
			got:       "1234",
			ret:       false,
			wantError: 1,
		},
		{
			name:      "mismatched type",
			expected:  "123",
			got:       123,
			ret:       false,
			wantError: 1,
		},
		{
			name:      "float64 equal",
			expected:  float64(123),
			got:       float64(123),
			ret:       true,
			wantError: 0,
		},
		{
			name:      "float64 unequal",
			expected:  float64(1234),
			got:       float64(123),
			ret:       false,
			wantError: 1,
		},
		{
			name:      "bool equal",
			expected:  true,
			got:       true,
			ret:       true,
			wantError: 0,
		},
		{
			name:      "bool unequal",
			expected:  false,
			got:       true,
			ret:       false,
			wantError: 1,
		},
		{
			name:      "list equal",
			expected:  []interface{}{"1", "2", "3"},
			got:       []interface{}{"1", "2", "3"},
			ret:       true,
			wantError: 0,
		},
		{
			name:      "list unequal element",
			expected:  []interface{}{"1", "2", "3"},
			got:       []interface{}{"1", "2", "3a"},
			ret:       false,
			wantError: 1,
		},
		{
			name:      "list unequal length",
			expected:  []interface{}{"1", "2", "3"},
			got:       []interface{}{"1", "2", "3", "4"},
			ret:       false,
			wantError: 1,
		},
		{
			name:      "list missing element",
			expected:  []interface{}{"1", "2", "3"},
			got:       []interface{}{"1", "2"},
			ret:       false,
			wantError: 1,
		},
		{
			name: "map equal",
			expected: map[string]interface{}{
				"a": "A",
				"b": "B",
			},
			got: map[string]interface{}{
				"a": "A",
				"b": "B",
			},
			ret:       true,
			wantError: 0,
		},
		{
			name: "map unequal element",
			expected: map[string]interface{}{
				"a": "A",
				"b": "B",
			},
			got: map[string]interface{}{
				"a": "A",
				"b": "Bc",
			},
			ret:       false,
			wantError: 1,
		},
		{
			name: "map extra element",
			expected: map[string]interface{}{
				"a": "A",
				"b": "B",
			},
			got: map[string]interface{}{
				"a": "A",
				"b": "B",
				"c": "C",
			},
			ret:       true,
			wantError: 0,
		},
		{
			name: "map missing element",
			expected: map[string]interface{}{
				"a": "A",
				"b": "B",
			},
			got: map[string]interface{}{
				"a": "A",
			},
			ret:       false,
			wantError: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockT := &bufferT{}
			assert.Equal(t, test.ret, match(mockT, test.expected, test.got))
			assert.Equal(t, test.wantError, mockT.count)
		})
	}
}

// bufferT implements TestingT. Its implementation of Errorf writes the output that would be produced by
// testing.T.Errorf to an internal bytes.Buffer.
type bufferT struct {
	buf   bytes.Buffer
	count int
}

func (t *bufferT) Errorf(format string, args ...interface{}) {
	// below is unused for now - we just check the error count
	t.count = t.count + 1

	// implementation of decorate is copied from testing.T
	decorate := func(s string) string {
		_, file, line, ok := runtime.Caller(3) // decorate + log + public function.
		if ok {
			// Truncate file name at last file name separator.
			if index := strings.LastIndex(file, "/"); index >= 0 {
				file = file[index+1:]
			} else if index = strings.LastIndex(file, "\\"); index >= 0 {
				file = file[index+1:]
			}
		} else {
			file = "???"
			line = 1
		}
		buf := new(bytes.Buffer)
		// Every line is indented at least one tab.
		buf.WriteByte('\t')
		fmt.Fprintf(buf, "%s:%d: ", file, line)
		lines := strings.Split(s, "\n")
		if l := len(lines); l > 1 && lines[l-1] == "" {
			lines = lines[:l-1]
		}
		for i, line := range lines {
			if i > 0 {
				// Second and subsequent lines are indented an extra tab.
				buf.WriteString("\n\t\t")
			}
			buf.WriteString(line)
		}
		buf.WriteByte('\n')
		return buf.String()
	}
	t.buf.WriteString(decorate(fmt.Sprintf(format, args...)))
}
