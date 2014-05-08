package main

//https://github.com/inatus/ssh-client-go
import (
	"bufio"
	"code.google.com/p/go.crypto/ssh"
	"flag"
	"fmt"
	"github.com/howeyc/gopass"
	"github.com/marpaia/chef-golang"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	//	"errors"
)

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
func getChefInfo(configFile string, chefNode string, sshPort int) (ipaddr string, err error) {
	c, err := chef.Connect(configFile)
	if err != nil {
		return "", err
	}
	c.SSLNoVerify = true

	// Print detailed information about a specific node
	node, ok, err := c.GetNode(chefNode)
	if err != nil {
		return "", err
	} else if !ok {
		return "", err
	}

	return node.Info.IPAddress + ":" + strconv.Itoa(sshPort), nil
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

func main() {
	var sshUser string
	var sshPassword string
	var chefNode string
	var chefServer string
	var configFile string
	var sshPort int
	flag.StringVar(&sshUser, "user", os.Getenv("USER"), "The username to connect to the remote server as")
	flag.StringVar(&sshPassword, "password", "", "The password to connect to the remote server with")
	flag.StringVar(&chefNode, "node", "", "The chef node name")
	flag.StringVar(&chefServer, "server", "", "The chef server name")
	flag.StringVar(&configFile, "config", "", "Optional knife.rb/client.rb path")
	flag.IntVar(&sshPort, "port", 22, "SSH port to connect to")
	flag.Parse()

	// Need to define at least a chef node
	if chefNode == "" {
		flag.Usage()
		os.Exit(1)
	}

	serverAddress, err := getChefInfo(configFile, chefNode, sshPort)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Get SSH session set up
	if sshPassword == "" {
		fmt.Print(sshUser + "@" + serverAddress + "'s Password: ")
		sshPassword = string(gopass.GetPasswdMasked())
	}

	clientConfig := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(sshPassword),
		},
	}

	conn, err := ssh.Dial("tcp", serverAddress, clientConfig)
	if err != nil {
		fmt.Println("Unable to connect to " + serverAddress)
		fmt.Println(err.Error())
		os.Exit(1)
	}

	defer conn.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := conn.NewSession()
	if err != nil {
		panic("Failed to create session: " + err.Error())
	}
	defer session.Close()

	// Spawn a handler for signals so we can send them
	// through the session to the remote host
	//handleSignals(*session)

	// Redirect Session IO to local machine
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	in, _ := session.StdinPipe()

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,      // disable echoing since we handle
		ssh.TTY_OP_ISPEED: 115200, // input speed = 115.2k baud ISDN!!
		ssh.TTY_OP_OSPEED: 115200, // output speed = 115.2k baud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		log.Fatalf("request for pseudo terminal failed: %s", err)
	}

	// Start remote shell
	// if err := session.Shell(); err != nil {
	// 	log.Fatalf("failed to start shell: %s", err)
	// }
	err = session.Shell()
	if err != nil {
		log.Fatalf("failed to start shell: %s", err)
	}

	//sessionWatchdog(*session, *conn)
	// Accepting commands until a clean exit
	for {
		reader := bufio.NewReader(os.Stdin)
		str, _ := reader.ReadString('\n')
		fmt.Fprint(in, str)
	}
}
