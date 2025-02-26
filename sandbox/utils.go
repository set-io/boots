package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func CleanPath(path string) string {
	if path == "" {
		return ""
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		path = filepath.Clean(string(os.PathSeparator) + path)
		path, _ = filepath.Rel(string(os.PathSeparator), path)
	}
	return filepath.Clean(path)
}

func ValidateID(id string) error {
	if len(id) < 1 {
		return ErrInvalidID
	}

	// Allowed characters: 0-9 A-Z a-z _ + - .
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_':
		case c == '+':
		case c == '-':
		case c == '.':
		default:
			return ErrInvalidID
		}
	}
	if string(os.PathSeparator)+id != CleanPath(string(os.PathSeparator)+id) {
		return ErrInvalidID
	}
	return nil
}

func SetParams(params *string, args []string, name string) {
	if args != nil {
		if len(args) > 1 {
			*params = fmt.Sprintf("%s %s", *params, fmt.Sprintf("%s=%s", name, strings.Join(args, " ")))
		} else {
			*params = fmt.Sprintf("%s %s", *params, fmt.Sprintf("%s=%s", name, args[0]))
		}
	}
}
