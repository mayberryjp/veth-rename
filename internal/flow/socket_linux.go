//go:build linux

package flow

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func withUDPSocket(conn net.Conn, operation func(int, int) error) error {
	socket, ok := conn.(syscall.Conn)
	if !ok {
		return fmt.Errorf("IPFIX connection does not expose its UDP socket")
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var operationErr error
	err = raw.Control(func(fd uintptr) {
		domain, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN)
		if err != nil {
			operationErr = err
			return
		}
		operationErr = operation(int(fd), domain)
	})
	return errors.Join(err, operationErr)
}

func configureUDP(conn net.Conn) error {
	err := withUDPSocket(conn, func(fd, domain int) error {
		switch domain {
		case unix.AF_INET:
			return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
		case unix.AF_INET6:
			return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
		default:
			return fmt.Errorf("unsupported IPFIX socket family %d", domain)
		}
	})
	if err != nil {
		return fmt.Errorf("enable IPFIX nonfragmenting path MTU discovery: %w", err)
	}
	return nil
}

func udpMessageBudget(conn net.Conn) (int, error) {
	budget := 0
	err := withUDPSocket(conn, func(fd, domain int) error {
		level, option, overhead := unix.IPPROTO_IP, unix.IP_MTU, 28
		switch domain {
		case unix.AF_INET:
		case unix.AF_INET6:
			level, option, overhead = unix.IPPROTO_IPV6, unix.IPV6_MTU, 48
		default:
			return fmt.Errorf("unsupported IPFIX socket family %d", domain)
		}
		mtu, err := unix.GetsockoptInt(fd, level, option)
		if err != nil {
			return err
		}
		budget = mtu - overhead
		if budget <= 0 {
			return fmt.Errorf("IPFIX path MTU %d is smaller than header overhead %d", mtu, overhead)
		}
		return nil
	})
	return budget, err
}
