package tracing

import (
	"syscall"
	"testing"
	"time"

	"github.com/Motmedel/ecs_go/ecs"
)

func TestGetBootTime(t *testing.T) {
	bootTime := GetBootTime()
	if bootTime.IsZero() {
		t.Fatal("GetBootTime returned zero time")
	}
	if bootTime.After(time.Now()) {
		t.Fatal("boot time is in the future")
	}
}

func TestGetBootTimeIdempotent(t *testing.T) {
	a := GetBootTime()
	b := GetBootTime()
	if !a.Equal(b) {
		t.Fatalf("GetBootTime returned different values: %v vs %v", a, b)
	}
}

func TestConvertEbpfTimestamp(t *testing.T) {
	bootTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	// 1 second in nanoseconds
	ts := uint64(1_000_000_000)
	result := ConvertEbpfTimestamp(ts, bootTime)
	expected := bootTime.Add(time.Second)
	if !result.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
}

func TestConvertEbpfTimestampToIso8601(t *testing.T) {
	bootTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	ts := uint64(500_000_000) // 0.5 seconds
	result := ConvertEbpfTimestampToIso8601(ts, bootTime)
	expected := "2025-06-15T12:00:00.5Z"
	if result != expected {
		t.Fatalf("expected %q, got %q", expected, result)
	}
}

func TestConvertEbpfTimestampToIso8601Zero(t *testing.T) {
	bootTime := time.Date(2025, 3, 10, 8, 30, 0, 0, time.UTC)
	result := ConvertEbpfTimestampToIso8601(0, bootTime)
	expected := "2025-03-10T08:30:00Z"
	if result != expected {
		t.Fatalf("expected %q, got %q", expected, result)
	}
}

func TestIpAddressFromEbpfIPv4(t *testing.T) {
	var addr [16]byte
	addr[0] = 192
	addr[1] = 168
	addr[2] = 1
	addr[3] = 100
	result := IpAddressFromEbpf(addr, syscall.AF_INET)
	expected := "192.168.1.100"
	if result != expected {
		t.Fatalf("expected %q, got %q", expected, result)
	}
}

func TestIpAddressFromEbpfIPv6(t *testing.T) {
	var addr [16]byte
	// ::1 (loopback)
	addr[15] = 1
	result := IpAddressFromEbpf(addr, syscall.AF_INET6)
	expected := "::1"
	if result != expected {
		t.Fatalf("expected %q, got %q", expected, result)
	}
}

func TestIpAddressFromEbpfUnknownFamily(t *testing.T) {
	var addr [16]byte
	result := IpAddressFromEbpf(addr, 9999)
	if result != "" {
		t.Fatalf("expected empty string, got %q", result)
	}
}

func TestEnrichWithSourceUserNilBase(t *testing.T) {
	EnrichWithSourceUser(nil, 1000) // should not panic
}

func TestEnrichWithSourceUser(t *testing.T) {
	base := &ecs.Base{}
	EnrichWithSourceUser(base, 1000)

	if base.Source == nil {
		t.Fatal("Source is nil")
	}
	if base.Source.User == nil {
		t.Fatal("Source.User is nil")
	}
	if base.Source.User.Id != "1000" {
		t.Fatalf("expected user id %q, got %q", "1000", base.Source.User.Id)
	}
}

func TestEnrichWithSourceUserExistingSource(t *testing.T) {
	base := &ecs.Base{Source: &ecs.Target{Ip: "10.0.0.1"}}
	EnrichWithSourceUser(base, 500)

	if base.Source.Ip != "10.0.0.1" {
		t.Fatal("existing Source.Ip was overwritten")
	}
	if base.Source.User == nil || base.Source.User.Id != "500" {
		t.Fatal("user not set correctly")
	}
}

func TestEnrichWithConnectionInformationNilBase(t *testing.T) {
	var src, dst [16]byte
	EnrichWithConnectionInformation(nil, src, 80, dst, 443, syscall.AF_INET) // should not panic
}

func TestEnrichWithConnectionInformationIPv4(t *testing.T) {
	base := &ecs.Base{}
	var src, dst [16]byte
	src[0], src[1], src[2], src[3] = 10, 0, 0, 1
	dst[0], dst[1], dst[2], dst[3] = 10, 0, 0, 2

	EnrichWithConnectionInformation(base, src, 12345, dst, 80, syscall.AF_INET)

	if base.Source == nil {
		t.Fatal("Source is nil")
	}
	if base.Source.Ip != "10.0.0.1" {
		t.Fatalf("expected source ip %q, got %q", "10.0.0.1", base.Source.Ip)
	}
	if base.Source.Port != 12345 {
		t.Fatalf("expected source port 12345, got %d", base.Source.Port)
	}
	if base.Destination == nil {
		t.Fatal("Destination is nil")
	}
	if base.Destination.Ip != "10.0.0.2" {
		t.Fatalf("expected destination ip %q, got %q", "10.0.0.2", base.Destination.Ip)
	}
	if base.Destination.Port != 80 {
		t.Fatalf("expected destination port 80, got %d", base.Destination.Port)
	}
	if base.Network == nil {
		t.Fatal("Network is nil")
	}
	if base.Network.Type != "ipv4" {
		t.Fatalf("expected network type %q, got %q", "ipv4", base.Network.Type)
	}
}

func TestEnrichWithConnectionInformationIPv6(t *testing.T) {
	base := &ecs.Base{}
	var src, dst [16]byte
	src[15] = 1 // ::1
	dst[15] = 2 // ::2

	EnrichWithConnectionInformation(base, src, 8080, dst, 443, syscall.AF_INET6)

	if base.Source.Ip != "::1" {
		t.Fatalf("expected source ip %q, got %q", "::1", base.Source.Ip)
	}
	if base.Destination.Ip != "::2" {
		t.Fatalf("expected destination ip %q, got %q", "::2", base.Destination.Ip)
	}
	if base.Network.Type != "ipv6" {
		t.Fatalf("expected network type %q, got %q", "ipv6", base.Network.Type)
	}
}

func TestEnrichWithConnectionInformationUnknownFamily(t *testing.T) {
	base := &ecs.Base{}
	var src, dst [16]byte
	EnrichWithConnectionInformation(base, src, 80, dst, 443, 9999)

	if base.Network != nil {
		t.Fatal("Network should be nil for unknown address family")
	}
}

func TestEnrichWithConnectionInformationTransportNilBase(t *testing.T) {
	var src, dst [16]byte
	EnrichWithConnectionInformationTransport(nil, src, 80, dst, 443, syscall.AF_INET, 6) // should not panic
}

func TestEnrichWithConnectionInformationTransportTCP(t *testing.T) {
	base := &ecs.Base{}
	var src, dst [16]byte
	src[0], src[1], src[2], src[3] = 10, 0, 0, 1
	dst[0], dst[1], dst[2], dst[3] = 10, 0, 0, 2

	EnrichWithConnectionInformationTransport(base, src, 12345, dst, 80, syscall.AF_INET, 6)

	if base.Network == nil {
		t.Fatal("Network is nil")
	}
	if base.Network.IanaNumber != "6" {
		t.Fatalf("expected iana number %q, got %q", "6", base.Network.IanaNumber)
	}
	if base.Network.Transport != "tcp" {
		t.Fatalf("expected transport %q, got %q", "tcp", base.Network.Transport)
	}
	if base.Network.Type != "ipv4" {
		t.Fatalf("expected network type %q, got %q", "ipv4", base.Network.Type)
	}
}

func TestEnrichWithConnectionInformationTransportUDP(t *testing.T) {
	base := &ecs.Base{}
	var src, dst [16]byte

	EnrichWithConnectionInformationTransport(base, src, 0, dst, 0, syscall.AF_INET, 17)

	if base.Network.Transport != "udp" {
		t.Fatalf("expected transport %q, got %q", "udp", base.Network.Transport)
	}
}

func TestEnrichWithConnectionInformationTransportZero(t *testing.T) {
	base := &ecs.Base{}
	var src, dst [16]byte

	EnrichWithConnectionInformationTransport(base, src, 80, dst, 443, syscall.AF_INET, 0)

	if base.Network == nil {
		t.Fatal("Network should be set by connection enrichment")
	}
	if base.Network.IanaNumber != "" {
		t.Fatalf("expected empty iana number, got %q", base.Network.IanaNumber)
	}
	if base.Network.Transport != "" {
		t.Fatalf("expected empty transport, got %q", base.Network.Transport)
	}
}

func TestEnrichWithConnectionInformationTransportUnknownProtocol(t *testing.T) {
	base := &ecs.Base{}
	var src, dst [16]byte

	EnrichWithConnectionInformationTransport(base, src, 0, dst, 0, syscall.AF_INET, 255)

	if base.Network.IanaNumber != "255" {
		t.Fatalf("expected iana number %q, got %q", "255", base.Network.IanaNumber)
	}
	if base.Network.Transport != "" {
		t.Fatalf("expected empty transport for unknown protocol, got %q", base.Network.Transport)
	}
}

func TestEnrichWithProcessInformationNilBase(t *testing.T) {
	var title [16]byte
	EnrichWithProcessInformation(nil, 1, title, 0, 1000, 1000) // should not panic
}

func TestEnrichWithProcessInformation(t *testing.T) {
	base := &ecs.Base{}
	var title [16]byte
	copy(title[:], "myprocess")

	EnrichWithProcessInformation(base, 42, title, 1, 1000, 1001)

	if base.Process == nil {
		t.Fatal("Process is nil")
	}
	if base.Process.Pid != 42 {
		t.Fatalf("expected pid 42, got %d", base.Process.Pid)
	}
	if base.Process.Title != "myprocess" {
		t.Fatalf("expected title %q, got %q", "myprocess", base.Process.Title)
	}
	if base.Process.User == nil || base.Process.User.Id != "1000" {
		t.Fatalf("expected user id %q, got %v", "1000", base.Process.User)
	}
	if base.Process.Group == nil || base.Process.Group.Id != "1001" {
		t.Fatalf("expected group id %q, got %v", "1001", base.Process.Group)
	}
	if base.Process.Parent == nil || base.Process.Parent.Pid != 1 {
		t.Fatalf("expected parent pid 1, got %v", base.Process.Parent)
	}
}

func TestEnrichWithProcessInformationTitleNullTrimmed(t *testing.T) {
	base := &ecs.Base{}
	var title [16]byte
	copy(title[:], "cat") // remaining bytes are 0x00

	EnrichWithProcessInformation(base, 1, title, 0, 0, 0)

	if base.Process.Title != "cat" {
		t.Fatalf("expected title %q, got %q", "cat", base.Process.Title)
	}
}
