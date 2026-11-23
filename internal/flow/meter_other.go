//go:build !linux

package flow

import (
	"fmt"
	"veth-rename/internal/firewall"
)

func platformReady() error {
	return fmt.Errorf("eBPF monitoring requires Linux 6.6+")
}

func validateFirewall(*firewall.Policy) error { return platformReady() }

func monotonic() (uint64, error) {
	return 0, fmt.Errorf("eBPF monitoring requires Linux")
}

type meterOptions struct {
	samplingRate, filter uint32
	collector            Key
	firewall             *firewall.Policy
}

func attachMeter(Interface, meterOptions) (meter, error) {
	return nil, platformReady()
}
