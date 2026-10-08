// Package skylink provides distributed device connectivity (mini SkyOS).
package skylink

import (
	"encoding/json"
	"fmt"
	"time"
)

// DeviceType categorises devices in the mesh.
type DeviceType string

const (
	DevicePhone  DeviceType = "phone"
	DevicePC     DeviceType = "pc"
	DeviceServer DeviceType = "server"
	DeviceEdge   DeviceType = "edge"
)

// DeviceStatus represents the current state of a device.
type DeviceStatus string

const (
	StatusOnline  DeviceStatus = "online"
	StatusOffline DeviceStatus = "offline"
	StatusBusy    DeviceStatus = "busy"
	StatusLowPower DeviceStatus = "low_power"
)

// DeviceProfile is the capability and status manifest for a device.
type DeviceProfile struct {
	PeerID       string            `json:"peer_id"`
	DeviceType   DeviceType        `json:"device_type"`
	Capabilities []string          `json:"capabilities"`
	Status       DeviceStatus      `json:"status"`
	Load         float64           `json:"load"`
	Battery      *int              `json:"battery,omitempty"`
	Agents       []string          `json:"agents"`
	ContentRoots []string          `json:"content_roots"`
	Endpoint     string            `json:"endpoint"`
	Version      string            `json:"version"`
	LastSeen     time.Time         `json:"last_seen"`
	Trusted      bool              `json:"trusted"`
	Attrs        map[string]string `json:"attrs,omitempty"`
}

// Validate checks required fields.
func (p *DeviceProfile) Validate() error {
	if p.PeerID == "" {
		return fmt.Errorf("skylink: PeerID required")
	}
	if p.DeviceType == "" {
		return fmt.Errorf("skylink: DeviceType required")
	}
	return nil
}

// ToJSON serialises the profile.
func (p *DeviceProfile) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// DeviceProfileFromJSON deserialises a profile.
func DeviceProfileFromJSON(data []byte) (*DeviceProfile, error) {
	var p DeviceProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
