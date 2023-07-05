package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	hostname := flag.String("hostname", "", "hostname to connect to")
	port := flag.Int("port", 22, "port to connect to")
	timeout := flag.Int64("timeout", 10, "timeout for connecting")
	command := flag.String("command", "uname -a", "command to run")
	username := flag.String("username", "root", "username to use")
	password := flag.String("password", "", "password")
	keyfile := flag.String("keyfile", "", "path to private key")
	ignoreKeyError := flag.Bool("ignore-key-error", false,
		"ignore errors for private key")
	flag.Parse()

	if *hostname == "" || *username == "" ||
		(*password == "" && *keyfile == "") {
		flag.Usage()
		return
	}

	_timeout := time.Duration(*timeout * int64(time.Second))

	config := &ssh.ClientConfig{
		User:            *username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         _timeout,
		Auth:            []ssh.AuthMethod{},
	}

	if *password != "" {
		config.Auth = append(config.Auth,
			[]ssh.AuthMethod{ssh.Password(*password)}[0])
	}

	if *keyfile != "" {
		key, err := ioutil.ReadFile(*keyfile)
		if err != nil {
			log.Print(err)
			if !*ignoreKeyError {
				return
			}
		} else {
			signer, err := ssh.ParsePrivateKey(key)
			if err != nil {
				log.Print(err)
				if !*ignoreKeyError {
					return
				}
			} else {
				config.Auth = append(config.Auth,
					[]ssh.AuthMethod{
						ssh.PublicKeys(signer)}[0])
			}
		}
	}

	remote := fmt.Sprint(*hostname, ":", *port)
	conn, err := ssh.Dial("tcp", remote, config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), _timeout)
	defer cancel()

	stdout := make(chan []byte, 1)
	stderr := make(chan error, 1)

	go func(ctx context.Context) {
		if out, err := session.CombinedOutput(*command); err != nil {
			stderr <- err
		} else {
			stdout <- out
		}
	}(ctx)

	select {
	case res := <-stdout:
		fmt.Println(string(res))
	case err := <-stderr:
		log.Fatal(err)
	case <-ctx.Done():
		log.Fatal(ctx.Err())
	}
}
