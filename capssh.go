package capssh

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Method uint

const (
	PrivateKey Method = iota
	Password
)

type SSH interface {
	Cmd(string) error
	Sftp() error
}

type capssh struct {
	client *ssh.Client
	addr   string
	user   string
	method Method
	cert   string // pem/password
}

func NewClient(addr, user string, cert string, method Method) (*capssh, error) {
	if len(cert) <= 0 {
		return nil, errors.New("PrivateKey is null")
	}
	var auth ssh.AuthMethod
	if method == PrivateKey {

		signer, err := ssh.ParsePrivateKey([]byte(cert))
		if err != nil {
			return nil, err
		}
		auth = ssh.PublicKeys(signer)
	} else if method == Password {

		auth = ssh.Password(cert)

	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	return &capssh{client: client, user: user, cert: cert, addr: addr, method: method}, nil
}

func (s *capssh) Cmd(cmd string) (string, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	return string(output), nil
}

func (s *capssh) Sftp(dstFilePath, srcFilPath string) error {
	// 创建sftp客户端
	client, err := sftp.NewClient(s.client)
	if err != nil {
		return err
	}
	defer client.Close()

	// 获取传输文件
	srcfile, err := os.Open(srcFilPath)
	if err != nil {
		return err
	}
	defer srcfile.Close()

	// 创建上传目录
	dstdir := "./" + dstFilePath
	if err := client.MkdirAll(dstdir); err != nil {
		return err
	}

	// 创建远程文件
	filename := filepath.Base(srcFilPath)
	dstfiledir := filepath.Join(dstdir, filename)
	dstfile, err := client.Create(dstfiledir)

	if err != nil {
		return err
	}
	defer dstfile.Close()

	// 上传文件
	_, err = io.Copy(dstfile, srcfile)
	if err != nil {
		return err
	}

	err = client.Chmod(dstfiledir, 0777)
	if err != nil {
		return err
	}
	return nil
}
