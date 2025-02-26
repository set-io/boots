package sandbox

import (
	"errors"
	"fmt"
	"github.com/set-io/boots/utils"
	"github.com/set-io/boots/utils/process"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type InitProcess struct {
	*ExecProcess
	exec bool
}

type ExecProcess struct {
	id       int
	Args     []string
	Env      []string
	UID, GID int
	Cwd      string
	Stdout   io.Writer
	Stderr   io.Writer
	Init     bool
	Terminal bool
}

func (e *ExecProcess) start() error {
	if debug {
		log.Printf("start exec process: %s\n", strings.Join(e.Args, " "))
	}
	user, _ := utils.SearchArrays(e.Env, User)
	config := &ssh.ClientConfig{User: user}
	pwd, _ := utils.SearchArrays(e.Env, Cipher)
	config.Auth = []ssh.AuthMethod{ssh.Password(pwd)}
	config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	config.Timeout = 10 * time.Second
	addr, _ := utils.SearchArrays(e.Env, Addr)
	if debug {
		log.Printf("start ssh session: %s, %s, %s\n", user, pwd, addr)
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", addr), config)
	if err != nil {
		return fmt.Errorf("failed to dial: %s", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %s", err)
	}
	defer session.Close()

	if e.Terminal {
		if debug {
			log.Println("start terminal session")
		}
		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}

		fd := int(os.Stdin.Fd())
		state, err := term.MakeRaw(fd)
		if err != nil {
			return fmt.Errorf("failed to set terminal to raw mode: %s", err)
		}
		defer term.Restore(fd, state)

		width, height, err := term.GetSize(fd)
		if err != nil {
			return fmt.Errorf("failed to get terminal size: %s", err)
		}

		if err := session.RequestPty("xterm", height, width, modes); err != nil {
			return fmt.Errorf("failed to request PTY: %s", err)
		}

		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		session.Stdin = os.Stdin

		if err := session.Shell(); err != nil {
			return fmt.Errorf("failed to start shell: %s", err)
		}
		return session.Wait()
	}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin
	return session.Run(strings.Join(e.Args, " "))
}

func (p *InitProcess) pid() int {
	return p.id
}

func (p *InitProcess) start() error {
	if p.exec {
		if debug {
			log.Println("start exec process")
		}
		return p.ExecProcess.start()
	}
	cmd := exec.Command(p.Args[0], p.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	cmd.Stdout = p.Stdout
	cmd.Stderr = p.Stderr
	if debug {
		log.Printf("start init process: %v\n", cmd.String())
	}
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting command: %v", err)
	}
	p.id = cmd.Process.Pid
	if debug {
		log.Printf("start process: %d\n", cmd.Process.Pid)
	}
	return nil
}

func (p *InitProcess) terminate() error {
	return errors.New("init process cannot be terminated")
}

func (p *InitProcess) wait() (*os.ProcessState, error) {
	return nil, errors.New("init process cannot be waited on")
}

func (p *InitProcess) startTime() (uint64, error) {
	stat, err := process.Stat(p.pid())
	return stat.StartTime, err
}

func (p *InitProcess) signal(_ os.Signal) error {
	return errors.New("init process cannot receive signals")
}

func (p *InitProcess) forwardChildLogs() chan error {
	return make(chan error)
}

type nonChildProcess struct {
	processPid       int
	processStartTime uint64
}

func (p *nonChildProcess) start() error {
	return errors.New("restored process cannot be started")
}

func (p *nonChildProcess) pid() int {
	return p.processPid
}

func (p *nonChildProcess) terminate() error {
	return errors.New("restored process cannot be terminated")
}

func (p *nonChildProcess) wait() (*os.ProcessState, error) {
	return nil, errors.New("restored process cannot be waited on")
}

func (p *nonChildProcess) startTime() (uint64, error) {
	return p.processStartTime, nil
}

func (p *nonChildProcess) signal(s os.Signal) error {
	proc, err := os.FindProcess(p.processPid)
	if err != nil {
		return err
	}
	return proc.Signal(s)
}

func (p *nonChildProcess) forwardChildLogs() chan error {
	return nil
}

type runtimeProcess struct {
	*os.Process
}

func newRuntimeProcess() (parentProcess, error) {
	pid := os.Getpid()
	p, err := os.FindProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("error finding process: %v", err)
	}
	return &runtimeProcess{
		Process: p,
	}, nil
}

func (p *runtimeProcess) pid() int {
	return p.Pid
}

func (p *runtimeProcess) start() error {
	return errors.New("runtime process cannot be started")
}

func (p *runtimeProcess) terminate() error {
	err := p.Kill()
	if _, wErr := p.wait(); err == nil {
		err = wErr
	}
	return err
}

func (p *runtimeProcess) wait() (*os.ProcessState, error) {
	return p.Wait()
}

func (p *runtimeProcess) startTime() (uint64, error) {
	stat, err := process.Stat(p.pid())
	return stat.StartTime, err
}

func (p *runtimeProcess) signal(sig os.Signal) error {
	s, ok := sig.(unix.Signal)
	if !ok {
		return errors.New("os: unsupported signal type")
	}
	return unix.Kill(p.pid(), s)
}

func (p *runtimeProcess) forwardChildLogs() chan error {
	return make(chan error)
}
