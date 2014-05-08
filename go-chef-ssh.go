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

// This is our way of translating the OS Signals into
// appropriate SSH signals
func handleSignals(session ssh.Session) {
	c := make(chan os.Signal, 1)

	signal.Notify(c)

	// Transform syscall signals to ssh signals
	go func() {
		for sig := range c {
			switch sig {
			case syscall.SIGABRT:
				_ = session.Signal(ssh.SIGABRT)
			case syscall.SIGALRM:
				_ = session.Signal(ssh.SIGALRM)
			case syscall.SIGFPE:
				_ = session.Signal(ssh.SIGFPE)
			case syscall.SIGHUP:
				_ = session.Signal(ssh.SIGHUP)
			case syscall.SIGILL:
				_ = session.Signal(ssh.SIGILL)
			case syscall.SIGINT:
				_ = session.Signal(ssh.SIGINT)
			case syscall.SIGKILL:
				_ = session.Signal(ssh.SIGKILL)
			case syscall.SIGPIPE:
				_ = session.Signal(ssh.SIGPIPE)
			case syscall.SIGQUIT:
				_ = session.Signal(ssh.SIGQUIT)
			case syscall.SIGSEGV:
				_ = session.Signal(ssh.SIGSEGV)
			case syscall.SIGTERM:
				_ = session.Signal(ssh.SIGTERM)
			case syscall.SIGUSR1:
				_ = session.Signal(ssh.SIGUSR1)
			case syscall.SIGUSR2:
				_ = session.Signal(ssh.SIGUSR2)
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
func myreaders(readers ...io.Reader) {
	// Transform syscall signals to ssh signals
	for _, reader := range readers {
		go func() {
			io.Copy(os.Stdout, reader)
		}()
	}
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
		ssh.ECHO:          0,      // disable echoing since we handle
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
	//serr, _ := session.StderrPipe()
	sin, _ := session.StdinPipe()

	// defer sout.Close()
	// defer serr.Close()
	defer sin.Close()

	if err := session.Shell(); err != nil {
		panic("failed to start shell: " + err.Error())
	}

	myreaders(sout)
	mywriter(sin)
	defer session.Wait()

}
