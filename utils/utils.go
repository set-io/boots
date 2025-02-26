package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func ParseSize(s, unit string) (int, error) {
	sz := strings.TrimRight(s, "gGmMkK")
	if len(sz) == 0 {
		return -1, fmt.Errorf("%q:can't parse as num[gGmMkK]:%w", s, strconv.ErrSyntax)
	}
	amt, err := strconv.ParseUint(sz, 0, 0)
	if err != nil {
		return -1, err
	}
	if len(s) > len(sz) {
		unit = s[len(sz):]
	}
	switch unit {
	case "G", "g":
		return int(amt) << 30, nil
	case "M", "m":
		return int(amt) << 20, nil
	case "K", "k":
		return int(amt) << 10, nil
	case "":
		return int(amt), nil
	}
	return -1, fmt.Errorf("can not parse %q as num[gGmMkK]:%w", s, strconv.ErrSyntax)
}
func WriteJSON(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func SearchArrays(arr []string, key string) (string, bool) {
	key += "="
	for _, s := range arr {
		if val, ok := strings.CutPrefix(s, key); ok {
			return val, true
		}
	}
	return "", false
}

func Annotations(labels []string) (bundle string, userAnnotations map[string]string) {
	userAnnotations = make(map[string]string)
	for _, l := range labels {
		name, value, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		if name == "bundle" {
			bundle = value
		} else {
			userAnnotations[name] = value
		}
	}
	return
}

func OpenPipeFile(filename string) (*os.File, error) {
	return os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
}

func MustOpenPipeFile(filename string) *os.File {
	f, err := OpenPipeFile(filename)
	if err != nil {
		panic(fmt.Errorf("open pipe file error: %s", err))
	}
	return f
}

func GetParams(args []string, key string) string {
	for _, l := range args {
		name, value, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		if name == key {
			return value
		}
	}
	return ""
}

func PipePath(path string) string {
	return filepath.Join(path, "pipe.status")
}

func StateFile(path string) string {
	return filepath.Join(path, "state.json")
}

func FifoFile(path string) string {
	return filepath.Join(path, "sync.fifo")
}

func compareVersion(v1, v2 string) int {
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	for i := 0; i < len(v1Parts) && i < len(v2Parts); i++ {
		v1Part, _ := strconv.Atoi(v1Parts[i])
		v2Part, _ := strconv.Atoi(v2Parts[i])

		if v1Part < v2Part {
			return -1
		} else if v1Part > v2Part {
			return 1
		}
	}
	if len(v1Parts) < len(v2Parts) {
		return -1
	} else if len(v1Parts) > len(v2Parts) {
		return 1
	}
	return 0
}

func CheckKernelVersion(minVersion string) error {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %v", err)
	}
	kernelVersion := strings.TrimSpace(string(output))
	re := regexp.MustCompile(`^(\d+\.\d+\.\d+)`)
	match := re.FindStringSubmatch(kernelVersion)
	if len(match) < 2 {
		return fmt.Errorf("failed to parse kernel version: %s", kernelVersion)
	}
	currentVersion := match[1]
	if compareVersion(currentVersion, minVersion) < 0 {
		return fmt.Errorf("Current kernel version %s is less than %s. Please upgrade your kernel.\n", currentVersion, minVersion)
	}
	return nil
}
