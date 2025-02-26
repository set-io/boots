package process

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type State rune

const (
	Dead        State = 'X'
	DiskSleep   State = 'D'
	Running     State = 'R'
	Sleeping    State = 'S'
	Stopped     State = 'T'
	TracingStop State = 't'
	Zombie      State = 'Z'
	Parked      State = 'P'
	Idle        State = 'I'
)

func (s State) String() string {
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
	State     State
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
	stat.State = State(data[0])

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
