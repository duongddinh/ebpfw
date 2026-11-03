//go:build !linux

package runtime

import (
	"errors"
	"io"
)

func Run(string, []string) error {
	return errors.New("XDP enforcement requires Linux; policy editing and validation work here")
}
func Stats(string, io.Writer) error { return errors.New("XDP enforcement requires Linux") }
