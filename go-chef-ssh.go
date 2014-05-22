package main

import (
	// "bufio"
	"code.google.com/p/go.crypto/ssh"
	"flag"
	"fmt"
	"github.com/howeyc/gopass"
	"github.com/marpaia/chef-golang"
	"net"
	// "log"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	//	"errors"
)

type configops struct {
	sshUser     string
	sshPassword string
	chefNode    string
	chefServer  string
	configFile  string
	sshPort     int
}

type Signal string

// Updating signals to include additional/all signals
const (
	SIGHUP    Signal = "HUP"
	SIGINT    Signal = "INT"
	SIGQUIT   Signal = "QUIT"
	SIGILL    Signal = "ILL"
	SIGTRAP   Signal = "TRAP"
	SIGABRT   Signal = "ABRT"
	SIGEMT    Signal = "EMT"
	SIGFPE    Signal = "FPE"
	SIGKILL   Signal = "KILL"
	SIGBUS    Signal = "BUS"
	SIGSEGV   Signal = "SEGV"
	SIGSYS    Signal = "SYS"
	SIGPIPE   Signal = "PIPE"
	SIGALRM   Signal = "ALRM"
	SIGTERM   Signal = "TERM"
	SIGURG    Signal = "URG"
	SIGSTOP   Signal = "STOP"
	SIGTSTP   Signal = "TSTP"
	SIGCONT   Signal = "CONT"
	SIGCHLD   Signal = "CHLD"
	SIGTTIN   Signal = "TTIN"
	SIGTTOU   Signal = "TTOU"
	SIGIO     Signal = "IO"
	SIGXCPU   Signal = "XCPU"
	SIGXFSZ   Signal = "XFSZ"
	SIGVTALRM Signal = "VTALRM"
	SIGPROF   Signal = "PROF"
	SIGWINCH  Signal = "WINCH"
	SIGINFO   Signal = "INFO"
	SIGUSR1   Signal = "USR1"
	SIGUSR2   Signal = "USR2"
)

var signals = map[Signal]int{
	SIGHUP:    1,
	SIGINT:    2,
	SIGQUIT:   3,
	SIGILL:    4,
	SIGTRAP:   5,
	SIGABRT:   6,
	SIGEMT:    7,
	SIGFPE:    8,
	SIGKILL:   9,
	SIGBUS:    10,
	SIGSEGV:   11,
	SIGSYS:    12,
	SIGPIPE:   13,
	SIGALRM:   14,
	SIGTERM:   15,
	SIGURG:    16,
	SIGSTOP:   17,
	SIGTSTP:   18,
	SIGCONT:   19,
	SIGCHLD:   20,
	SIGTTIN:   21,
	SIGTTOU:   22,
	SIGIO:     23,
	SIGXCPU:   24,
	SIGXFSZ:   25,
	SIGVTALRM: 26,
	SIGPROF:   27,
	SIGWINCH:  28,
	SIGINFO:   29,
	SIGUSR1:   30,
	SIGUSR2:   31,
}

// This is our way of translating the OS Signals into
// appropriate SSH signals
func handleSignals(session *ssh.Session, sin io.WriteCloser) {

	c := make(chan os.Signal, 1)
	// d := make(chan *ssh.Signal, 1)
	signal.Notify(c)

	// Transform syscall signals to ssh signals
	go func() {
		// sigs := new(Signal)
		// fmt.Println(ssh.Signal(signals[SIGIO]))
		for sig := range c {
			switch sig {
			case syscall.SIGABRT:
				err := session.Signal(ssh.Signal(signals[SIGABRT]))
				if err != nil {
					fmt.Println("Unable to send signal")
				}
			case syscall.SIGALRM:
				err := session.Signal(ssh.Signal(signals[SIGALRM]))
				if err != nil {
					fmt.Println("Unable to send signal")
				}
			case syscall.SIGFPE:
				err := session.Signal(ssh.Signal(signals[SIGFPE]))
				if err != nil {
					fmt.Println("Unable to send signal")
				}
			case syscall.SIGHUP:
				err := session.Signal(ssh.Signal(signals[SIGHUP]))
				if err != nil {
					fmt.Println("Unable to send signal")
				}
			// case syscall.SIGILL:
			// 	err := session.Signal(ssh.Signal(signals[SIGILL)
			case syscall.SIGINT:
				err := session.Signal(ssh.SIGKILL)

				// err = session.Signal(ssh.SIGKILL)
				// err = session.Signal(ssh.SIGKILL)
				// err = session.Signal(ssh.SIGKILL)
				if err != nil {
					fmt.Println("Unable to send signal")
				}
				// err = session.Signal(ssh.Signal(signals[SIGKILL]))

				//
				// // signal.Notify(d)
				// fmt.Print("SIGINT!")
				// fmt.Fprintf(sin, syscall.SIGINT)
				// signal.Notify(d)
				// _ = session.Signal(ssh.SIGINT)
			case syscall.SIGSTOP:
				err := session.Signal(ssh.Signal(signals[SIGSTOP]))
				if err != nil {
					fmt.Println("Unable to send signal")
				}
			case syscall.SIGTSTP:
				err := session.Signal(ssh.Signal(signals[SIGTSTP]))
				if err != nil {
					fmt.Println("Unable to send signal")
				}
			// case syscall.SIGKILL:
			// 	err := session.Signal(ssh.Signal(signals[SIGKILL]))
			// 	if err != nil {
			// 		fmt.Println("Unable to send signal")
			// 	}
			case syscall.SIGPIPE:
				err := session.Signal(ssh.Signal(signals[SIGPIPE]))
				if err != nil {
					fmt.Println("Unable to send signal")
				}
			case syscall.SIGQUIT:
				err := session.Signal(ssh.Signal(signals[SIGQUIT]))
				if err != nil {
					fmt.Println("Unable to send signal")
				}
			case syscall.SIGSEGV:
				err := session.Signal(ssh.Signal(signals[SIGSEGV]))
				if err != nil {
					fmt.Println("Unable to send signal")
				}
			case syscall.SIGTERM:
				err := session.Signal(ssh.Signal(signals[SIGTERM]))
				if err != nil {
					fmt.Println("Unable to send signal")
				}
			case syscall.SIGUSR1:
				err := session.Signal(ssh.Signal(signals[SIGUSR1]))
				if err != nil {
					fmt.Println("Unable to send signal")
				}
			case syscall.SIGUSR2:
				err := session.Signal(ssh.Signal(signals[SIGUSR2]))
				if err != nil {
					fmt.Println("Unable to send signal")
				}
			}
		}
	}()
}

// This sets up our connection to the chef server and queries
// it for the node's IP address
func getChefInfo(config *configops) (ipaddr string, err error) {
	c, err := chef.Connect(config.configFile)
	if err != nil {
		return "", err
	}
	c.SSLNoVerify = true

	// Print detailed information about a specific node
	node, ok, err := c.GetNode(config.chefNode)
	if err != nil {
		return "", err
	} else if !ok {
		return "", err
	}

	return node.Info.IPAddress + ":" + strconv.Itoa(config.sshPort), nil
}

// Maybe this will allow for session termination on exit
func mystdoutreader(reader io.Reader) {
	// Transform syscall signals to ssh signals
	go func() {
		io.Copy(os.Stdout, reader)
	}()
}

func mystderrreader(reader io.Reader) {
	// Transform syscall signals to ssh signals
	go func() {
		io.Copy(os.Stderr, reader)
	}()
}

// Maybe this will allow for session termination on exit
func mywriter(writer io.Writer) {
	// Transform syscall signals to ssh signals
	go func() {
		io.Copy(writer, os.Stdin)
	}()
}

// Maybe this will allow for session termination on exit
func sessionWatchdog(session ssh.Session, conn ssh.Client) {
	// Transform syscall signals to ssh signals
	go func() {
		if session.Wait() == nil {
			session.Close()
			conn.Close()
		}
	}()
}

// Handle oll of our CLI input and add them to a configops struct
func parseFlags() (config *configops, err error) {
	configobj := new(configops)
	flag.StringVar(&configobj.sshUser, "user", os.Getenv("USER"), "The username to connect to the remote server as")
	flag.StringVar(&configobj.sshPassword, "password", "", "The password to connect to the remote server with")
	flag.StringVar(&configobj.chefNode, "node", "", "The chef node name")
	flag.StringVar(&configobj.chefServer, "server", "", "The chef server name")
	flag.StringVar(&configobj.configFile, "config", "", "Optional knife.rb/client.rb path")
	flag.IntVar(&configobj.sshPort, "port", 22, "SSH port to connect to")
	flag.Parse()

	// Need to define at least a chef node
	if configobj.chefNode == "" {
		flag.Usage()
		os.Exit(1)
	}

	if configobj.sshPassword == "" {
		fmt.Print(configobj.sshUser + "@" + configobj.chefNode + "'s Password: ")
		configobj.sshPassword = string(gopass.GetPasswdMasked())
	}

	return configobj, nil
}

// Yummy yummy main!
func main() {
	configcli, err := parseFlags()
	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	serverAddress, err := getChefInfo(configcli)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Get SSH session set up
	clientConfig := &ssh.ClientConfig{
		User: configcli.sshUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(configcli.sshPassword),
		},
	}

	// Connect to the remote host
	conn, err := net.Dial("tcp", serverAddress)
	if err != nil {
		fmt.Println("Unable to connect to " + serverAddress)
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Make sure we clean up
	defer conn.Close()

	// Generate a client
	c, chans, reqs, err := ssh.NewClientConn(conn, serverAddress, clientConfig)
	if err != nil {
		fmt.Println("Unable to connect to " + serverAddress)
		fmt.Println(err.Error())
		os.Exit(1)
	}

	client := ssh.NewClient(c, chans, reqs)

	// Establish a session
	session, err := client.NewSession()
	if err != nil {
		panic("Failed to create session: " + err.Error())
	}

	// Make sure we clean up
	defer session.Close()

	// Set up terminal modes
	modes := ssh.TerminalModes{
		// Works
		ssh.ECHO:          0, // disable echoing since we handle
		ssh.ECHOCTL:       1, // enable echoing of control characters
		ssh.VINTR:         3, // Ctrl+c for interrupt
		ssh.IXANY:         1,
		ssh.ECHOK:         0,
		ssh.VEOL:          255,
		ssh.VEOL2:         255,
		ssh.IMAXBEL:       1,
		ssh.TTY_OP_ISPEED: 115200, // input speed = 115.2k baud ISDN!!
		ssh.TTY_OP_OSPEED: 115200, // output speed = 115.2k baud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		panic("request for pseudo terminal failed:" + err.Error())
	}

	// Redirect Session IO to local machine
	// session.Stdout = os.Stdout
	// session.Stderr = os.Stderr
	sout, _ := session.StdoutPipe()
	serr, _ := session.StderrPipe()
	sin, _ := session.StdinPipe()

	// defer sout.Close()
	// defer serr.Close()
	defer sin.Close()

	if err := session.Shell(); err != nil {
		panic("failed to start shell: " + err.Error())
	}

	handleSignals(session, sin)
	mystdoutreader(sout)
	mystderrreader(serr)
	mywriter(sin)
	defer session.Wait()

}
