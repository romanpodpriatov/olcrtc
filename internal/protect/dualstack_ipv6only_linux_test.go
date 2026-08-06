//go:build linux

package protect_test

// ai-generated: whole file, the regression test for the IPv6-only carrier-auth
// fix (#1).
//
// The condition this pins cannot be reached on an ordinary network: a machine
// with IPv4 dials the A record and passes whether the code is right or not. So
// the test builds the condition instead of waiting for it - a sealed network
// namespace holding one IPv6 address and no IPv4 route at all, where the A
// record answers ENETUNREACH exactly as an IPv6-only carrier does.
//
// The namespace is created inside the test process with CLONE_NEWNET and
// CLONE_NEWUSER, so it needs no root, adds no interface to the host, touches no
// firewall rule or sysctl, and is gone when the process exits.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/protect"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	nsChildEnv = "OLCRTC_DUALSTACK_NS_CHILD"
	nsTestName = "TestDialsDualStackHostWithoutIPv4"

	// testV6 is the only address the namespace carries.
	testV6 = "fd00:d1a1::1"
	// testV4 is assigned nowhere, so connecting to it gives ENETUNREACH
	// immediately - no route, not a timeout.
	testV4   = "10.99.0.1"
	testHost = "dualstack.test"

	// unreachableDNS stands in for the IPv4 literal mobile clients are
	// configured with (1.1.1.1:53 on iOS).
	unreachableDNS = "1.1.1.1:53"
)

func TestDialsDualStackHostWithoutIPv4(t *testing.T) {
	if os.Getenv(nsChildEnv) == "1" {
		runDualStackCases(t)
		return
	}
	out, err := reexecInNetNS(t.Context())
	if err != nil {
		if isNamespaceDenied(out, err) {
			t.Skipf("network namespaces unavailable here, cannot build an IPv6-only interface: %v\n%s", err, out)
		}
		t.Fatalf("namespace child failed: %v\n%s", err, out)
	}
	t.Logf("namespace child output:\n%s", out)
}

// reexecInNetNS runs this test again inside a fresh network and user namespace.
func reexecInNetNS(ctx context.Context) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate test binary: %w", err)
	}
	//nolint:gosec // re-executes this very test binary, path from os.Executable
	cmd := exec.CommandContext(ctx, exe, "-test.run=^"+nsTestName+"$", "-test.v")
	cmd.Env = append(os.Environ(), nsChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("run child: %w", err)
	}
	return string(out), nil
}

// isNamespaceDenied separates "this kernel will not let us" from a real failure.
func isNamespaceDenied(out string, err error) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// The child started, so namespaces work; the failure is ours.
		return strings.Contains(out, "cannot configure namespace")
	}
	return true
}

func runDualStackCases(t *testing.T) {
	t.Helper()
	if err := configureNamespace(t.Context()); err != nil {
		t.Fatalf("cannot configure namespace: %v", err)
	}
	assertNoIPv4Route(t)

	httpAddr := startEchoServer(t)
	_, port, err := net.SplitHostPort(httpAddr)
	if err != nil {
		t.Fatalf("split http addr: %v", err)
	}
	url := "http://" + net.JoinHostPort(testHost, port) + "/"

	t.Run("unreachable_dns_server_does_not_end_resolution", func(t *testing.T) {
		stub := startStubDNS(t, &stubDNS{})
		// The IPv4 literal comes first, exactly as a mobile client is
		// configured. It cannot be reached from here at all.
		setDNS(t, unreachableDNS, stub)
		mustGet(t, url)
	})

	// The headline case from the issue: a dual-stack host, an interface with no
	// IPv4, and a dial that has to end up on the AAAA record.
	t.Run("dual_stack_host_connects_over_ipv6", func(t *testing.T) {
		stub := startStubDNS(t, &stubDNS{})
		setDNS(t, stub)
		mustGet(t, url)
	})

	t.Run("protector_rejecting_ipv6_names_both_families", func(t *testing.T) {
		stub := startStubDNS(t, &stubDNS{})
		setDNS(t, stub)
		protect.Protector = rejectIPv6Streams
		t.Cleanup(func() { protect.Protector = nil })

		_, err := fetch(t.Context(), url) //nolint:bodyclose // the dial must fail
		if err == nil {
			t.Fatal("dial succeeded while the protector rejected every IPv6 socket")
		}
		msg := err.Error()
		if !strings.Contains(msg, "ipv6:") || !strings.Contains(msg, "ipv4:") {
			t.Fatalf("error names only one family, so the dead leg stays hidden: %v", err)
		}
		if !errors.Is(err, protect.ErrProtectorRejected) {
			t.Fatalf("error does not carry the protector rejection: %v", err)
		}
	})
}

// configureNamespace gives the namespace a single IPv6 address and nothing else.
func configureNamespace(ctx context.Context) error {
	for _, args := range [][]string{
		{"addr", "add", testV6 + "/128", "dev", "lo"},
		{"link", "set", "lo", "up"},
	} {
		//nolint:gosec // fixed argv, configuring the sealed namespace
		cmd := exec.CommandContext(ctx, "ip", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

// assertNoIPv4Route proves the condition under test is real: the A record has
// no route, so a dial that picks it fails outright.
func assertNoIPv4Route(t *testing.T) {
	t.Helper()
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(t.Context(), "tcp4", net.JoinHostPort(testV4, "80"))
	if err == nil {
		_ = conn.Close()
		t.Fatalf("%s is reachable, so this namespace does not model an IPv6-only link", testV4)
	}
	if !errors.Is(err, syscall.ENETUNREACH) && !errors.Is(err, syscall.EHOSTUNREACH) {
		t.Fatalf("want no route to %s, got %v", testV4, err)
	}
	t.Logf("confirmed: no IPv4 route to %s (%v)", testV4, err)
}

func setDNS(t *testing.T, servers ...string) {
	t.Helper()
	protect.SetDNSServers(servers...)
	t.Cleanup(func() { protect.SetDNSServers() })
}

func mustGet(t *testing.T, url string) {
	t.Helper()
	resp, err := fetch(t.Context(), url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != reachedOverIPv6 {
		t.Fatalf("body = %q, want %q", body, reachedOverIPv6)
	}
}

const reachedOverIPv6 = "reached-over-ipv6"

func startEchoServer(t *testing.T) string {
	t.Helper()
	var config net.ListenConfig
	listener, err := config.Listen(t.Context(), "tcp6", net.JoinHostPort(testV6, "0"))
	if err != nil {
		t.Fatalf("listen http: %v", err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, reachedOverIPv6)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

// stubDNS answers testHost with an A record that has no route and an AAAA
// record that does - the shape of every dual-stack host reached from a link
// without IPv4.
type stubDNS struct{}

func startStubDNS(t *testing.T, stub *stubDNS) string {
	t.Helper()
	var config net.ListenConfig
	conn, err := config.ListenPacket(t.Context(), "udp6", net.JoinHostPort(testV6, "0"))
	if err != nil {
		t.Fatalf("listen dns: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go stub.serve(conn)
	return conn.LocalAddr().String()
}

func (s *stubDNS) serve(conn net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		reply, err := s.answer(buf[:n])
		if err != nil {
			continue
		}
		_, _ = conn.WriteTo(reply, from)
	}
}

func (s *stubDNS) answer(query []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, fmt.Errorf("parse query: %w", err)
	}
	question, err := parser.Question()
	if err != nil {
		return nil, fmt.Errorf("parse question: %w", err)
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: true,
	})
	builder.EnableCompression()
	if err := startSections(&builder, question); err != nil {
		return nil, err
	}
	if err := addAnswer(&builder, question); err != nil {
		return nil, err
	}
	msg, err := builder.Finish()
	if err != nil {
		return nil, fmt.Errorf("build reply: %w", err)
	}
	return msg, nil
}

func startSections(builder *dnsmessage.Builder, question dnsmessage.Question) error {
	if err := builder.StartQuestions(); err != nil {
		return fmt.Errorf("start questions: %w", err)
	}
	if err := builder.Question(question); err != nil {
		return fmt.Errorf("add question: %w", err)
	}
	if err := builder.StartAnswers(); err != nil {
		return fmt.Errorf("start answers: %w", err)
	}
	return nil
}

func addAnswer(builder *dnsmessage.Builder, question dnsmessage.Question) error {
	name := strings.TrimSuffix(question.Name.String(), ".")
	if !strings.EqualFold(name, testHost) {
		return nil
	}
	header := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
	//nolint:exhaustive // the stub serves A and AAAA; every other type gets NOERROR with no answer
	switch question.Type {
	case dnsmessage.TypeA:
		var addr [4]byte
		copy(addr[:], net.ParseIP(testV4).To4())
		if err := builder.AResource(header, dnsmessage.AResource{A: addr}); err != nil {
			return fmt.Errorf("add a record: %w", err)
		}
	case dnsmessage.TypeAAAA:
		var addr [16]byte
		copy(addr[:], net.ParseIP(testV6).To16())
		if err := builder.AAAAResource(header, dnsmessage.AAAAResource{AAAA: addr}); err != nil {
			return fmt.Errorf("add aaaa record: %w", err)
		}
	default:
		// Nothing else is asked for, and NOERROR with no answer is the
		// right reply to a question this stub does not serve.
	}
	return nil
}

// rejectIPv6Streams mirrors a host protector that cannot pin an IPv6 socket -
// what an interface lookup filtered on AF_INET degrades to on a link that has
// no IPv4 address to find one by.
//
// Only stream sockets are refused. The real thing refuses every IPv6 socket,
// but the stub resolver in this namespace is itself only reachable over IPv6,
// so refusing its datagrams would end the test at resolution and never reach
// the dial this case is about.
func rejectIPv6Streams(fd int) bool {
	domain, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_DOMAIN)
	if err != nil {
		return false
	}
	if domain != syscall.AF_INET6 {
		return true
	}
	sockType, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return false
	}
	return sockType != syscall.SOCK_STREAM
}

// fetch issues a GET through the protected HTTP client.
func fetch(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := protect.NewHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	return resp, nil
}
