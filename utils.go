package boots

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"io/ioutil"
	"encoding/json"
	"io"
)

type ProcState rune

const (
	Dead        ProcState = 'X'
	DiskSleep   ProcState = 'D'
	Running     ProcState = 'R'
	Sleeping    ProcState = 'S'
	Stopped     ProcState = 'T'
	TracingStop ProcState = 't'
	Zombie      ProcState = 'Z'
	Parked      ProcState = 'P'
	Idle        ProcState = 'I'
)

func (s ProcState) String() string {
	switch s {
	case Dead:
		return "dead"
	case DiskSleep:
		return "disk sleep"
	case Running:
		return "running"
	case Sleeping:
		return "sleeping"
	case Stopped:
		return "stopped"
	case TracingStop:
		return "tracing stop"
	case Zombie:
		return "zombie"
	case Parked:
		return "parked"
	case Idle:
		return "idle"
	default:
		return fmt.Sprintf("unknown (%c)", s)
	}
}

type Stat_t struct {
	Name      string
	State     ProcState
	StartTime uint64
}

func Stat(pid int) (stat Stat_t, err error) {
	bytes, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return stat, err
	}
	return parseStat(string(bytes))
}

func parseStat(data string) (stat Stat_t, err error) {
	const minAfterName = 20*2 + 1

	first := strings.IndexByte(data, '(')
	if first < 0 || first+minAfterName >= len(data) {
		return stat, fmt.Errorf("invalid stat data (no comm or too short): %q", data)
	}

	last := strings.LastIndexByte(data, ')')
	if last <= first || last+minAfterName >= len(data) {
		return stat, fmt.Errorf("invalid stat data (no comm or too short): %q", data)
	}

	stat.Name = data[first+1 : last]

	data = data[last+2:]
	stat.State = ProcState(data[0])

	skipSpaces := 22 - 3
	for first = 0; skipSpaces > 0 && first < len(data); first++ {
		if data[first] == ' ' {
			skipSpaces--
		}
	}
	i := strings.IndexByte(data[first:], ' ')
	if i < 0 {
		return stat, fmt.Errorf("invalid stat data (too short): %q", data)
	}
	stat.StartTime, err = strconv.ParseUint(data[first:first+i], 10, 64)
	if err != nil {
		return stat, fmt.Errorf("invalid stat data (bad start time): %w", err)
	}
	return stat, nil
}

func CheckSystemLimits() {
    var rLimit syscall.Rlimit
    err := syscall.Getrlimit(syscall.RLIMIT_AS, &rLimit)
    if err == nil {
        log.Printf("Address Space Limits - Cur: %d, Max: %d\n", rLimit.Cur, rLimit.Max)
    }
    maxMapCount, err := ioutil.ReadFile("/proc/sys/vm/max_map_count")
    if err == nil {
        log.Printf("Max Map Count: %s", string(maxMapCount))
    }
}

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
