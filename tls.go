package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type detectInfo struct {
	Result bool
	Msg    string
	Start  *time.Time
	End    *time.Time
}

// TLS implements a config for TLS
type TLS struct {
	Host    string
	Timeout time.Duration
}

func CreateTlsProbe(host string) *TLS {
	return &TLS{
		Host:    host,
		Timeout: 30 * time.Second,
	}
}

// DoProbe return the checking result
func (t *TLS) DoProbe() *detectInfo {
	addr := t.Host
	conn, err := net.DialTimeout("tcp", addr, t.Timeout)
	if err != nil {
		return &detectInfo{false, fmt.Sprintf("tcp dial error: %v", err), nil, nil}
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetLinger(0)
	}
	defer conn.Close()

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	tconn := tls.Client(conn, &tls.Config{
		RootCAs:    nil,
		ServerName: hostname,
	})

	ctx, cancel := context.WithTimeout(context.Background(), t.Timeout)
	defer cancel()
	err = tconn.HandshakeContext(ctx)
	if err != nil {
		return &detectInfo{false, fmt.Sprintf("tls handshake error: %v", err), nil, nil}
	}

	var LatestEnd *time.Time
	var Start *time.Time
	for _, cert := range tconn.ConnectionState().PeerCertificates {
		valid := true
		valid = valid && !time.Now().After(cert.NotAfter)
		valid = valid && !time.Now().Before(cert.NotBefore)

		if !valid {
			//log.Errorf("host %v cert expired", t.Host)
			return &detectInfo{false, fmt.Sprintf("certificate is expired or not yet valid"), nil, nil}
		}

		if LatestEnd == nil {
			LatestEnd = &cert.NotAfter
			Start = &cert.NotBefore
		}
		log.Infof("===%v %v", cert.NotBefore, cert.NotAfter)
		/*
			if !cert.NotAfter.Before(*latestEnd) {
				latestEnd = &cert.NotBefore
				Start = &cert.NotAfter
			}
		*/
	}

	return &detectInfo{true, "OK", Start, LatestEnd}
}
