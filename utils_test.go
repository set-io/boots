package boots_test

import (
	"errors"
	"strconv"
	"testing"

	"github.com/set-io/boots"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		unit     string
		expected int
		err      error
	}{
		{"Valid Gigabytes", "5G", "", 5 << 30, nil},
		{"Valid Megabytes", "10M", "", 10 << 20, nil},
		{"Valid Kilobytes", "20K", "", 20 << 10, nil},
		{"Valid Bytes", "1000", "", 1000, nil},
		{"Valid with unit parameter", "5", "G", 5 << 30, nil},
		{"Invalid empty string", "", "", -1, strconv.ErrSyntax},
		{"Invalid format", "5X", "", -1, strconv.ErrSyntax},
		{"Invalid number", "abc", "", -1, strconv.ErrSyntax},
		{"Case insensitive", "5g", "", 5 << 30, nil},
		{"Large number", "9223372036854775807", "", 9223372036854775807, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := boots.ParseSize(tt.s, tt.unit)
			if (err != nil) != (tt.err != nil) {
				t.Errorf("ParseSize() error = %v, wantErr %v", err, tt.err)
				return
			}
			if err != nil && !errors.Is(err, tt.err) {
				t.Errorf("ParseSize() error = %v, wantErr %v", err, tt.err)
				return
			}
			if got != tt.expected {
				t.Errorf("ParseSize() = %v, want %v", got, tt.expected)
			}
		})
	}
}
