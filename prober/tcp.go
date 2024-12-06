package prober

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"regexp"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ribbybibby/ssl_exporter/v2/config"
)

// ProbeTCP performs a tcp probe
func ProbeTCP(ctx context.Context, logger log.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	tlsConfig, err := newTLSConfig(target, registry, &module.TLSConfig)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close()

	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("Error setting deadline")
	}

	if module.TCP.StartTLS != "" {
		err = startTLS(logger, conn, module.TCP.StartTLS)
		if err != nil {
			return err
		}
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	return tlsConn.Handshake()
}

type queryResponse struct {
	expect      []string
	send        string
	sendBytes   []byte
	expectBytes []byte
}

var (
	// These are the protocols for which I had servers readily available to test
	// against. There are plenty of other protocols that should be added here in
	// the future.
	//
	// See openssl s_client for more examples:
	//  https://github.com/openssl/openssl/blob/openssl-3.0.0-alpha3/apps/s_client.c#L2229-L2728
	//
	// Expect is a slice to make possible to check for more than one match
	// this is needed to follow SMTP RFC - you must send any command only after
	// you get status code with space after it, f.e.: "250-" mean we need wait, and "250 " is final command.
	startTLSqueryResponses = map[string][]queryResponse{
		"smtp": []queryResponse{
			queryResponse{
				expect: []string{"^220 "},
			},
			queryResponse{
				send: "EHLO prober",
			},
			queryResponse{
				expect: []string{"^250(-| )STARTTLS", "^250 "},
			},
			queryResponse{
				send: "STARTTLS",
			},
			queryResponse{
				expect: []string{"^220 "},
			},
		},
		"ftp": []queryResponse{
			queryResponse{
				expect: []string{"^220"},
			},
			queryResponse{
				send: "AUTH TLS",
			},
			queryResponse{
				expect: []string{"^234"},
			},
		},
		"imap": []queryResponse{
			queryResponse{
				expect: []string{"OK"},
			},
			queryResponse{
				send: ". CAPABILITY",
			},
			queryResponse{
				expect: []string{"STARTTLS"},
			},
			queryResponse{
				expect: []string{"OK"},
			},
			queryResponse{
				send: ". STARTTLS",
			},
			queryResponse{
				expect: []string{"OK"},
			},
		},
		"postgres": []queryResponse{
			queryResponse{
				sendBytes: []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f},
			},
			queryResponse{
				expectBytes: []byte{0x53},
			},
		},
		"pop3": []queryResponse{
			queryResponse{
				expect: []string{"OK"},
			},
			queryResponse{
				send: "STLS",
			},
			queryResponse{
				expect: []string{"OK"},
			},
		},
	}
)

// startTLS will send the STARTTLS command for the given protocol
func startTLS(logger log.Logger, conn net.Conn, proto string) error {
	var err error

	qr, ok := startTLSqueryResponses[proto]
	if !ok {
		return fmt.Errorf("STARTTLS is not supported for %s", proto)
	}

	scanner := bufio.NewScanner(conn)
	for _, v := range qr {
		if len(v.expect) != 0 {
			var match bool
			countMatch := 0
			for scanner.Scan() {
				level.Debug(logger).Log("msg", fmt.Sprintf("read line: %s", scanner.Text()))
				for _, ve := range v.expect {
					match, err = regexp.Match(ve, scanner.Bytes())
					if err != nil {
						return err
					}
					if match {
						countMatch++
						level.Debug(logger).Log("msg", fmt.Sprintf("regex: %s matched: %s", ve, scanner.Text()))
					}
				}
				if countMatch == len(v.expect) {
					break
				}
			}
			if scanner.Err() != nil {
				return scanner.Err()
			}
			if countMatch != len(v.expect) {
				return fmt.Errorf("regex: %s didn't match: %s", v.expect, scanner.Text())
			}
		}
		if len(v.expectBytes) > 0 {
			buffer := make([]byte, len(v.expectBytes))
			_, err = io.ReadFull(conn, buffer)
			if err != nil {
				return nil
			}
			level.Debug(logger).Log("msg", fmt.Sprintf("read bytes: %x", buffer))
			if bytes.Compare(buffer, v.expectBytes) != 0 {
				return fmt.Errorf("read bytes %x didn't match with expected bytes %x", buffer, v.expectBytes)
			} else {
				level.Debug(logger).Log("msg", fmt.Sprintf("expected bytes %x matched with read bytes %x", v.expectBytes, buffer))
			}
		}
		if v.send != "" {
			level.Debug(logger).Log("msg", fmt.Sprintf("sending line: %s", v.send))
			if _, err := fmt.Fprintf(conn, "%s\r\n", v.send); err != nil {
				return err
			}
		}
		if len(v.sendBytes) > 0 {
			level.Debug(logger).Log("msg", fmt.Sprintf("sending bytes: %x", v.sendBytes))
			if _, err = conn.Write(v.sendBytes); err != nil {
				return err
			}
		}
	}
	return nil
}
