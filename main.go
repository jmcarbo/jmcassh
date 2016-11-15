// Based on server_complex.go at https://github.com/Scalingo/go-ssh-examples/
package main

import (
	"github.com/kardianos/service"
	"runtime"
	"encoding/base64"
	//"encoding/binary"
	"errors"
	"fmt"
	//"io"
	"log"
	"net"
	"os"
	"os/exec"
	//"sync"
	//"syscall"
	//"unsafe"

	//"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
	"flag"
)

// Configuration variables
var (
	IPAddress = flag.String("ipaddress", "0.0.0.0", "IP address")
	Port = flag.String("port", "2222", "server port")
	PublicKey = flag.String("key", "", "client publickey")
	ServiceUserName = flag.String("service-username", "", "Service username ")
	ServicePassword = flag.String("service-password", "", "Service password")
	User = flag.String("user", "", "client user")
	Version, HCUser, HCKey string
	defaultShell = "sh" // Shell used if the SHELL environment variable isn't set
	logger service.Logger

	// Public keys used for authentication.  Equivalent of the SSH authorized_hosts files
	authPublicKeys = map[string]string{
		"user": "AAAAC3NzaC1lZDI1NTE5AAAAIADi9ZoVZstck6ELY0EIB863kD4qp5i6DYpQJHkwBiEo",
		//"user2": "AAAAC3NzaC1lZDI1NTE5AAAAIADi9ZoVZstck6ELY0EIB863kD4qp5i6DYpQJHkwBiEo",
	}

	// SSH server host identification key
	hostKeyBytes = []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCbwxBo/3QT+gE3R2U0m71gJvCeLY5wYzaaDBXd6J59HQAAAJDpU9P06VPT
9AAAAAtzc2gtZWQyNTUxOQAAACCbwxBo/3QT+gE3R2U0m71gJvCeLY5wYzaaDBXd6J59HQ
AAAEDJR51JvnXwYB6ZDMIHqtE1ke12AfQ/T0Fc5OZ5FOmiRpvDEGj/dBP6ATdHZTSbvWAm
8J4tjnBjNpoMFd3onn0dAAAACXJvb3RAa2FsaQECAwQ=
-----END OPENSSH PRIVATE KEY-----`)

	sshServerConfig = &ssh.ServerConfig{
		//ServerVersion:     "SSH-2.0-OpenSSH_7.3p1 Debian-1",
		ServerVersion:     "",
		PublicKeyCallback: publicKeyCallback,
	}
)

type program struct{}


func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}

func (p *program) run() {
	startSSH()
	// Do work here
}
func (p *program) Stop(s service.Service) error {
	// Stop should not block. Return with a few seconds.
	return nil
}
// An SSH server is represented by a ServerConfig, which holds
// certificate details and handles authentication of ServerConns.

func startSSH() {

	//sshServerConfig =

	// You can generate a keypair with 'ssh-keygen -t rsa -C "test@example.com"'
	/*privateBytes, err := ioutil.ReadFile("./id_rsa")

	if err != nil {
		log.Fatal("Failed to load private key (./id_rsa)")
	}
	*/

	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		log.Fatal("Failed to parse host key")
	}

	sshServerConfig.AddHostKey(hostKey)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp4", *IPAddress + ":" + *Port)
	if err != nil {
		log.Fatalf("failed to listen on " + *IPAddress + ":" +  *Port)
	}

	// Accept all connections
	log.Printf("listening on %s:%s", IPAddress, Port)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection (%s)", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshServerConfig)
		if err != nil {
			log.Printf("failed to handshake (%s)", err)
			continue
		}

		// Check remote address
		log.Printf("new connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

		// Print incoming out-of-band Requests
		go handleRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}
}

func handleRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		log.Printf("recieved out-of-band request: %+v", req)
	}
}

/*
// Start assigns a pseudo-terminal tty os.File to c.Stdin, c.Stdout,
// and c.Stderr, calls c.Start, and returns the File of the tty's
// corresponding pty.
func PtyRun(c *exec.Cmd, tty *os.File) (err error) {
	defer tty.Close()
	c.Stdout = tty
	c.Stdin = tty
	c.Stderr = tty
	c.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}
	return c.Start()
}
*/
func GetDefaultShell() string {
	switch runtime.GOOS {
	case "windows": 
		return "CMD.EXE"
	
	case "linux": 
		return "sh"
	
	default:
		return "sh"
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if t := newChannel.ChannelType(); t != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel (%s)", err)
			continue
		}

		/*
		// allocate a terminal for this channel
		log.Print("creating pty...")
		// Create new pty
		f, tty, err := pty.Open()
		if err != nil {
			log.Printf("could not start pty (%s)", err)
			continue
		}
		*/

		var shell string
		shell = os.Getenv("SHELL")
		if shell == "" {
			shell = GetDefaultShell()
		}

		// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
		go func(in <-chan *ssh.Request) {
			for req := range in {
				//log.Printf("%v %s", req.Payload, req.Payload)
				ok := false
				switch req.Type {
				case "exec":
					ok = true
					command := string(req.Payload[4 : req.Payload[3]+4])
					log.Println(command)
					var cmd *exec.Cmd
					if runtime.GOOS == "windows" {
						cmd = exec.Command(shell, []string{"/c", command }...)
					} else {
						cmd = exec.Command(shell, []string{"-c", command}...)
					}

					cmd.Stdout = channel
					cmd.Stderr = channel
					cmd.Stdin = channel

					err := cmd.Start()
					if err != nil {
						log.Printf("could not start command (%s)", err)
						continue
					}

					// teardown session
					go func() {
						_, err := cmd.Process.Wait()
						if err != nil {
							log.Printf("failed to exit bash (%s)", err)
						}
						channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						channel.Close()
						log.Printf("session closed")
					}()
				case "shell":
					ok = false
					/*
					cmd := exec.Command(shell)
					cmd.Env = []string{"TERM=xterm"}
					err := PtyRun(cmd, tty)
					if err != nil {
						log.Printf("%s", err)
					}

					// Teardown session
					var once sync.Once
					close := func() {
						channel.Close()
						log.Printf("session closed")
					}

					// Pipe session to bash and visa-versa
					go func() {
						io.Copy(channel, f)
						once.Do(close)
					}()

					go func() {
						io.Copy(f, channel)
						once.Do(close)
					}()

					// We don't accept any commands (Payload),
					// only the default shell.
					if len(req.Payload) == 0 {
						ok = true
					}
					*/
				case "pty-req":
					ok = false
					/*
					// Responding 'ok' here will let the client
					// know we have a pty ready for input
					ok = true
					// Parse body...
					termLen := req.Payload[3]
					termEnv := string(req.Payload[4 : termLen+4])
					w, h := parseDims(req.Payload[termLen+4:])
					SetWinsize(f.Fd(), w, h)
					log.Printf("pty-req '%s'", termEnv)
					*/
				case "window-change":
					/*	
					w, h := parseDims(req.Payload)
					SetWinsize(f.Fd(), w, h)
					*/
					continue //no response
				}

				if !ok {
					log.Printf("declining %s request...", req.Type)
				}

				req.Reply(ok, nil)
			}
		}(requests)
	}
}

// =======================
/*
// parseDims extracts two uint32s from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	log.Printf("window resize %dx%d", w, h)
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

*/
// publicKeyCallback handles SSH key-based authentication
// This function is largely based off of the code in this post: https://lukevers.com/2016/05/01/ssh-as-authentication-for-web-applications
func publicKeyCallback(remoteConn ssh.ConnMetadata, remoteKey ssh.PublicKey) (*ssh.Permissions, error) {
	fmt.Println("Trying to auth user " + remoteConn.User())

	// Is it a valid user?
	authPublicKey, User := authPublicKeys[remoteConn.User()]
	if !User {
		fmt.Println("User does not exist")
		return nil, errors.New("User does not exist")
	}

	authPublicKeyBytes, err := base64.StdEncoding.DecodeString(authPublicKey)
	if err != nil {
		fmt.Println("Could not base64 decode key")
		return nil, errors.New("Could not base64 decode key")
	}

	// Parse public key
	parsedAuthPublicKey, err := ssh.ParsePublicKey([]byte(authPublicKeyBytes))
	if err != nil {
		fmt.Println("Could not parse public key")
		return nil, err
	}

	// Make sure the key types match
	if remoteKey.Type() != parsedAuthPublicKey.Type() {
		fmt.Println("Key types don't match")
		return nil, errors.New("Key types do not match")
	}

	remoteKeyBytes := remoteKey.Marshal()
	authKeyBytes := parsedAuthPublicKey.Marshal()

	// Make sure the key lengths match
	if len(remoteKeyBytes) != len(authKeyBytes) {
		fmt.Println("Key lengths don't match")
		return nil, errors.New("Keys do not match")
	}

	// Make sure every byte of the key matches up
	// TODO: This should be a constant time check
	keysMatch := true
	for i, b := range remoteKeyBytes {
		if b != authKeyBytes[i] {
			keysMatch = false
		}
	}

	if keysMatch == false {
		fmt.Println("Keys don't match")
		return nil, errors.New("Keys do not match")
	}

	return nil, nil
}

func main() {

	/*
	Config.KVDir = "kvstore"
	Config.Schedule = "1,10,20,30,40,50 * * * * *"
	hostname, _ := os.Hostname()
	Config.ClientID = strings.Replace(hostname, ".", "", -1) + Version
	Config.OS = runtime.GOOS 
	Config.ClusterID="PbWzOTNtFVHnftTYhAoANkkxDhJylS"
	Config.NatsURL="tls://nats.cluster.imim.cloud:4222"

	//configor.Load(&Config, path.Join("/", "controluka"+Version+".json"))
	if Config.NodeUUID == "" {
		Register()
	}
	*/
	//WriteConfig()

	svcFlag := flag.String("service", "", "Control the system service.")
	flag.Parse()
	if *PublicKey != "" && *User != "" {
		authPublicKeys[*User]= *PublicKey
	}
	if HCUser != "" && HCKey != "" {
		authPublicKeys[HCUser]= HCKey
	}

	svcConfig := &service.Config{
		Name:        "jmcasshd"+Version,
		DisplayName: "jmcasshd"+Version,
		Description: "jmcasshd"+Version,
	}

	if *ServiceUserName != "" && *ServicePassword != "" {
		svcConfig.UserName = *ServiceUserName
		svcConfig.Option = service.KeyValue(map[string]interface{}{"Password": *ServicePassword })
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	if len(*svcFlag) != 0 {
		if *svcFlag == "bootstrap" {
			err = service.Control(s, "install")
			if err != nil {
				log.Println(err)
			}
			err = service.Control(s, "start")
			if err != nil {
				log.Println(err)
			}
		} else if *svcFlag == "upgrade" {
			err = service.Control(s, "stop")
			if err != nil {
				log.Println(err)
			}
			err = service.Control(s, "uninstall")
			if err != nil {
				log.Println(err)
			}
			err = service.Control(s, "install")
			if err != nil {
				log.Println(err)
			}
			err = service.Control(s, "start")
			if err != nil {
				log.Println(err)
			}
		} else {
			err = service.Control(s, *svcFlag)
			if err != nil {
				log.Fatal(err)
			}
		}
		return
	}

	logger, err = s.Logger(nil)
	if err != nil {
		log.Fatal(err)
	}


	err = s.Run()
	if err != nil {
		logger.Error(err)
	}
}
