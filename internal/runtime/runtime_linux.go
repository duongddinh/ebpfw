// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"encoding/binary"
	"github.com/cilium/ebpf"
	"github.com/duongddinh/ebpfw/internal/policy"
)

// Install creates a complete immutable inner map, then publishes it with one
// map-in-map pointer update. In-flight packets retain their old map reference.
func Install(outer *ebpf.Map, template *ebpf.MapSpec, c policy.Config, order binary.ByteOrder) error {
	value, err := c.Encode(order)
	if err != nil {
		return err
	}
	spec := template.Copy()
	spec.Contents = nil
	inner, err := ebpf.NewMap(spec)
	if err != nil {
		return err
	}
	defer inner.Close()
	key := uint32(0)
	if err = inner.Update(key, value, ebpf.UpdateAny); err != nil {
		return err
	}
	if err = inner.Freeze(); err != nil {
		return err
	}
	return outer.Update(key, inner, ebpf.UpdateAny)
}
