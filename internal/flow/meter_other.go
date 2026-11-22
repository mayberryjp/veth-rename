//go:build !linux

package flow

import "fmt"

func platformReady() error {
	return fmt.Errorf("eBPF monitoring requires Linux 6.6+")
}

func monotonic() (uint64, error) {
	return 0, fmt.Errorf("eBPF monitoring requires Linux")
}

type meterOptions struct {
	samplingRate, filter uint32
	collector            Key
}

func attachMeter(Interface, meterOptions) (meter, error) {
	return nil, platformReady()
}
