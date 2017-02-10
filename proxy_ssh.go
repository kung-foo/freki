package freki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type SSHProxy struct {
	port      uint
	rsa_key   []byte
	processor *Processor
	log       Logger
	listener  net.Listener
}

type SshConn struct {
	io.ReadCloser
	log        Logger
	Conn       net.Conn
	config     *ssh.ServerConfig
	callbackFn func(c ssh.ConnMetadata) (*ssh.Client, error)
	wrapFn     func(c ssh.ConnMetadata, r io.ReadCloser) (io.ReadCloser, error)
	closeFn    func(c ssh.ConnMetadata) error
}

func NewSSHProxy(port uint) *SSHProxy {
	return &SSHProxy{
		port: port,
	}
}

func (s *SSHProxy) Port() uint {
	return s.port
}

func (s *SSHProxy) Type() string {
	return "proxy.ssh"
}

func (s *SSHProxy) Start(p *Processor) error {
	s.processor = p
	s.log = s.processor.log

	var err error

	// TODO: You probably want to use existing key
	if err := s.ssh_keyGen(); err != nil {
		s.log.Error(errors.Wrap(err, s.Type()))
		return err
	}

	// TODO: can I be more specific with the bind addr?
	s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.log.Error(errors.Wrap(err, s.Type()))
			continue
		}
		go s.handleConnection(conn)
	}

	return nil
}

func (s *SSHProxy) handleConnection(conn net.Conn) {
	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	ck := NewConnKeyByString(host, port)
	md := s.processor.Connections.GetByFlow(ck)
	if md == nil {
		s.log.Warnf("[prxy.ssh] untracked connection: %s", conn.RemoteAddr().String())
		return
	}

	target := md.Rule.targetURL

	if target.Scheme != "tcp" && target.Scheme != "docker" {
		s.log.Error(fmt.Errorf("unsupported scheme: %s", target.Scheme))
		return
	}

	s.log.Infof("[prxy.ssh] %s -> %s to %s", host, md.TargetPort, target.String())

	sshconn := s.initSSHConf(target.Host)
	sshconn.Conn = conn

	go func() {
		if err := sshconn.serve(s); err != nil {
			s.log.Error(errors.Wrap(interpreter("Error occurred while serving", err), s.Type()))
			return
		}
		s.log.Info("[prxy.ssh] Connection closed.")
	}()
}

func (p *SshConn) serve(s *SSHProxy) error {

	// Start ssh server with p.Conn as underlying transport
	serverConn, chans, reqs, err := ssh.NewServerConn(p.Conn, p.config)
	if err != nil {
		s.log.Error(errors.Wrap(interpreter(" failed to handshake", err), s.Type()))
		return (err)
	}

	clientConn, err := p.callbackFn(serverConn)
	if err != nil {
		s.log.Error(errors.Wrap(err, s.Type()))
		return (err)
	}

	defer func() {
		clientConn.Close()
		serverConn.Close()
	}()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {

		// proxyChan is a SSH channel on clientConn
		proxyChan, requests2, err2 := clientConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
		if err2 != nil {
			s.log.Error(errors.Wrap(interpreter(" Could not accept client channel: ", err2), s.Type()))
			return err
		}

		// 	Accept() accepts the channel creation request over server connection
		//	serverChan is returned SSH channel over serverConn
		serverChan, requests, err := newChannel.Accept()
		if err != nil {
			s.log.Error(errors.Wrap(interpreter(" Could not accept server channel: ", err), s.Type()))
			return err
		}

		// connect requests
		go func() {
			s.log.Info("[prxy.ssh] Waiting for request")

		r:
			for {
				var req *ssh.Request
				var dst ssh.Channel

				select {
				case req = <-requests:
					dst = proxyChan
				case req = <-requests2:
					dst = serverChan
				}

				//s.log.Infof("[prxy.ssh] Request: %s %s %s %s\n", dst, req.Type, req.WantReply, req.Payload)

				b, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
				if err != nil {
					s.log.Error(errors.Wrap(err, s.Type()))
				}

				if req.WantReply {
					req.Reply(b, nil)
				}

				switch req.Type {
				case "exit-status":
					break r
				default:
					s.log.Info("[prxy.ssh]", req.Type)
				}
			}

			serverChan.Close()
			proxyChan.Close()
		}()

		// Wrapped for recording session
		var wrappedServerChan io.ReadCloser = serverChan
		var wrappedProxyChan io.ReadCloser = proxyChan

		if p.wrapFn != nil {
			wrappedProxyChan, err = p.wrapFn(serverConn, proxyChan)
		}

		go func() {
			_, err := io.Copy(proxyChan, wrappedServerChan)
			if err != nil {
				s.log.Error(errors.Wrap(err, s.Type()))
			}
		}()

		go func() {
			_, err := io.Copy(serverChan, wrappedProxyChan)
			if err != nil {
				s.log.Error(errors.Wrap(err, s.Type()))
			}
		}()

		defer wrappedProxyChan.Close()
		defer wrappedServerChan.Close()
	}

	if p.closeFn != nil {
		p.closeFn(serverConn)
	}

	return nil
}

func (s *SSHProxy) initSSHConf(dest string) *SshConn {
	private, _ := ssh.ParsePrivateKey(s.rsa_key)

	var sessions map[net.Addr]map[string]interface{} = make(map[net.Addr]map[string]interface{})

	conf := &ssh.ServerConfig{

		// TODO: Authentication methods other than password
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.log.Infof("[prxy.ssh] Login attempt: %s, user %s password: %s", c.RemoteAddr(), c.User(), string(pass))

			clientConfig := &ssh.ClientConfig{}

			clientConfig.User = c.User()
			clientConfig.Auth = []ssh.AuthMethod{
				ssh.Password(string(pass)),
			}

			client, err := ssh.Dial("tcp", dest, clientConfig)
			if err != nil {
				s.log.Info("[prxy.ssh] Incorrect password for: %s", c.User())
			} else {
				sessions[c.RemoteAddr()] = map[string]interface{}{
					"username": c.User(),
					"password": string(pass),
				}
				sessions[c.RemoteAddr()]["client"] = client
			}
			return nil, err
		},
	}

	conf.AddHostKey(private)

	sshconn := &SshConn{}
	sshconn.wrapFn = func(c ssh.ConnMetadata, r io.ReadCloser) (io.ReadCloser, error) {
		// Record session
		sshconn.ReadCloser = r
		return sshconn, nil
	}
	sshconn.log = s.log
	sshconn.config = conf
	sshconn.callbackFn = func(c ssh.ConnMetadata) (*ssh.Client, error) {
		meta, _ := sessions[c.RemoteAddr()]

		s.log.Infof("[prxy.ssh] %v", meta)

		client := meta["client"].(*ssh.Client)
		s.log.Infof("[prxy.ssh] Connection accepted from: %s", c.RemoteAddr())

		return client, nil
	}
	sshconn.closeFn = func(c ssh.ConnMetadata) error {
		s.log.Infof("[prxy.ssh] Connection closed.")
		return nil
	}
	return sshconn
}

func (s *SSHProxy) ssh_keyGen() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2014)
	if err != nil {
		s.log.Error(errors.Wrap(err, s.Type()))
		return err
	}
	err = priv.Validate()
	if err != nil {
		s.log.Error(errors.Wrap(interpreter("Validation failed.", err), s.Type()))
		return err
	}

	priv_der := x509.MarshalPKCS1PrivateKey(priv)

	priv_blk := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   priv_der,
	}

	s.rsa_key = pem.EncodeToMemory(&priv_blk)
	// quick key test
	_, err = ssh.ParsePrivateKey(s.rsa_key)
	if err != nil {
		s.log.Error(errors.Wrap(err, s.Type()))
		return err
	}
	return nil
}

func interpreter(msg string, err error) error {
	return errors.New(fmt.Sprintf("%s  %s\n", msg, err))
}

func (rs *SshConn) Read(p []byte) (n int, err error) {
	n, err = rs.ReadCloser.Read(p)

	rs.log.Infof("[prxy.ssh] %s", string(p[:n]))

	return n, err
}

func (rs *SshConn) Close() error {
	return rs.ReadCloser.Close()
}

func (s *SSHProxy) Shutdown() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
