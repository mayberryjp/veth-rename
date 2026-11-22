//go:build !linux

package flow

import "net"

func configureUDP(net.Conn) error { return platformReady() }

func udpMessageBudget(net.Conn) (int, error) { return 0, platformReady() }
