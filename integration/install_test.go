package integration

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	"github.com/Relayward/relayward-sdk/protocol"
)

const (
	firstRegistrationToken   = "rwr_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	secondRegistrationToken  = "rwr_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	invalidRegistrationToken = "rwr_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	firstCredential          = "rwc_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
	secondCredential         = "rwc_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
	testNodeID               = "123e4567-e89b-42d3-a456-426614174000"
)

type initSystem struct {
	name       string
	dockerfile string
	ready      []string
	status     []string
	mainPID    []string
}

func TestInstallerWithSystemdAndOpenRC(t *testing.T) {
	if os.Getenv("RELAYWARD_AGENT_INSTALL_INTEGRATION") != "1" {
		t.Skip("set RELAYWARD_AGENT_INSTALL_INTEGRATION=1 to run privileged Docker installation tests")
	}
	releaseDirectory := requiredDirectory(t, "RELAYWARD_AGENT_RELEASE_DIR")
	releaseVersion := requiredEnvironment(t, "RELAYWARD_AGENT_RELEASE_VERSION")
	for _, token := range []string{firstRegistrationToken, secondRegistrationToken, invalidRegistrationToken} {
		if err := agentv1.ValidateRegistrationToken(token); err != nil {
			t.Fatalf("test registration token is invalid: %v", err)
		}
	}
	for _, credential := range []string{firstCredential, secondCredential} {
		if err := agentv1.ValidateCredential(credential); err != nil {
			t.Fatalf("test node credential is invalid: %v", err)
		}
	}
	for _, name := range []string{"install.sh", "relayward-agent-linux-amd64.tar.gz", "SHA256SUMS"} {
		if info, err := os.Stat(filepath.Join(releaseDirectory, name)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("release asset %s is unavailable: %v", name, err)
		}
	}

	center := newTestCenter(t)
	defer center.Close()
	for _, system := range []initSystem{
		{name: "systemd", dockerfile: "debian.Dockerfile", ready: []string{"systemctl", "show-environment"}, status: []string{"systemctl", "is-active", "relayward-agent.service"}, mainPID: []string{"systemctl", "show", "-p", "MainPID", "--value", "relayward-agent.service"}},
		{name: "openrc", dockerfile: "alpine.Dockerfile", ready: []string{"rc-status"}, status: []string{"rc-service", "relayward-agent", "status"}, mainPID: []string{"pidof", "relayward-agent"}},
	} {
		t.Run(system.name, func(t *testing.T) {
			testInstallation(t, system, releaseDirectory, releaseVersion, center)
		})
	}
}

type testCenter struct {
	server     *httptest.Server
	port       int
	mu         sync.RWMutex
	credential string
	sessions   atomic.Uint64
}

func newTestCenter(t *testing.T) *testCenter {
	t.Helper()
	value := &testCenter{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agent/register", value.register)
	mux.HandleFunc("GET /api/v1/agent/connect/{node_id}", value.connect)
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen for test center: %v", err)
	}
	value.port = listener.Addr().(*net.TCPAddr).Port
	value.server = httptest.NewUnstartedServer(mux)
	value.server.Listener = listener
	value.server.Start()
	return value
}

func (center *testCenter) Close() {
	center.server.Close()
}

func (center *testCenter) register(writer http.ResponseWriter, request *http.Request) {
	value, err := agentv1.DecodeRegisterRequest(request.Body)
	if err != nil {
		http.Error(writer, "invalid registration", http.StatusBadRequest)
		return
	}
	credential := ""
	switch value.Token {
	case firstRegistrationToken:
		credential = firstCredential
	case secondRegistrationToken:
		credential = secondCredential
	default:
		http.Error(writer, "invalid registration token", http.StatusUnauthorized)
		return
	}
	center.mu.Lock()
	center.credential = credential
	center.mu.Unlock()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(writer).Encode(agentv1.RegisterResponse{
		APIVersion: agentv1.APIVersion, NodeID: testNodeID, NodeName: "Install smoke", Credential: credential,
	})
}

func (center *testCenter) connect(writer http.ResponseWriter, request *http.Request) {
	center.mu.RLock()
	credential := center.credential
	center.mu.RUnlock()
	if request.PathValue("node_id") != testNodeID || request.Header.Get("Authorization") != "Bearer "+credential {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	connection, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	defer connection.Close()
	var hello protocol.Envelope
	if err := connection.ReadJSON(&hello); err != nil || hello.Type != agentv1.MessageAgentHello {
		return
	}
	centerHello, err := agentv1.NewEnvelope(agentv1.MessageCenterHello, agentv1.CenterHello{
		SessionID: "0123456789abcdef0123456789abcdef", HeartbeatIntervalSeconds: 5, ServerTime: time.Now().UTC(),
	})
	if err != nil || connection.WriteJSON(centerHello) != nil {
		return
	}
	center.sessions.Add(1)
	for {
		var envelope protocol.Envelope
		if err := connection.ReadJSON(&envelope); err != nil {
			return
		}
		if envelope.Type != agentv1.MessageAgentHeartbeat {
			continue
		}
		ack, err := agentv1.NewEnvelope(agentv1.MessageCenterHeartbeatAck, agentv1.HeartbeatAck{
			MessageID: envelope.ID, ServerTime: time.Now().UTC(),
		})
		if err != nil {
			return
		}
		ack.CorrelationID = envelope.ID
		if err := connection.WriteJSON(ack); err != nil {
			return
		}
	}
}

func testInstallation(t *testing.T, system initSystem, releaseDirectory, releaseVersion string, center *testCenter) {
	t.Helper()
	image := fmt.Sprintf("relayward-agent-install-%s:%d", system.name, os.Getpid())
	container := fmt.Sprintf("relayward-agent-install-%s-%d", system.name, os.Getpid())
	run(t, "docker", "build", "-f", filepath.Join("testdata", system.dockerfile), "-t", image, "testdata")
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", image).Run() })
	run(t, "docker", "run", "-d", "--privileged", "--cgroupns=host", "--name", container,
		"--add-host", "host.docker.internal:host-gateway", "--tmpfs", "/run", "--tmpfs", "/run/lock",
		"-v", releaseDirectory+":/release:ro", image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })

	eventually(t, 20*time.Second, func() bool { return runOK("docker", append([]string{"exec", container}, system.ready...)...) })
	sessions := center.sessions.Load()
	install(t, container, releaseVersion, center.port, firstRegistrationToken, true)
	eventually(t, 15*time.Second, func() bool { return center.sessions.Load() > sessions })
	assertServiceState(t, container, system)
	assertPathState(t, container)
	firstPID := commandOutput(t, append([]string{"exec", container}, system.mainPID...)...)

	sessions = center.sessions.Load()
	install(t, container, releaseVersion, center.port, secondRegistrationToken, true)
	eventually(t, 15*time.Second, func() bool { return center.sessions.Load() > sessions })
	secondPID := commandOutput(t, append([]string{"exec", container}, system.mainPID...)...)
	if firstPID == secondPID {
		t.Fatalf("%s Agent process was not restarted during credential replacement", system.name)
	}
	assertServiceState(t, container, system)

	sessions = center.sessions.Load()
	install(t, container, releaseVersion, center.port, invalidRegistrationToken, false)
	eventually(t, 15*time.Second, func() bool { return center.sessions.Load() > sessions })
	assertServiceState(t, container, system)

	run(t, "docker", "exec", container, "/usr/local/sbin/relayward-agent-uninstall", "--purge")
	if runOK("docker", "exec", container, "test", "-e", "/etc/relayward-agent") ||
		runOK("docker", "exec", container, "getent", "passwd", "relayward-agent") {
		t.Fatalf("%s purge left Agent configuration or service account behind", system.name)
	}
}

func install(t *testing.T, container, version string, port int, token string, wantSuccess bool) {
	t.Helper()
	arguments := []string{"exec", "-e", "RELAYWARD_REGISTRATION_TOKEN=" + token, container,
		"/release/install.sh", "--archive", "/release/relayward-agent-linux-amd64.tar.gz",
		"--checksums", "/release/SHA256SUMS", "--server-url", "http://host.docker.internal:" + strconv.Itoa(port),
		"--allow-insecure", "--version", version}
	command := exec.Command("docker", arguments...)
	output, err := command.CombinedOutput()
	if wantSuccess && err != nil {
		t.Fatalf("install Agent: %v\n%s", err, output)
	}
	if !wantSuccess && err == nil {
		t.Fatalf("installer accepted an invalid registration token:\n%s", output)
	}
	if strings.Contains(string(output), token) {
		t.Fatal("installer output exposed the registration token")
	}
}

func assertServiceState(t *testing.T, container string, system initSystem) {
	t.Helper()
	output := commandOutput(t, append([]string{"exec", container}, system.status...)...)
	if system.name == "systemd" && output != "active" {
		t.Fatalf("systemd service state = %q", output)
	}
}

func assertPathState(t *testing.T, container string) {
	t.Helper()
	want := map[string]string{
		"/etc/relayward-agent/config.json":       "640:root:relayward-agent",
		"/var/lib/relayward-agent/identity.json": "600:relayward-agent:relayward-agent",
	}
	for path, expected := range want {
		actual := commandOutput(t, "exec", container, "stat", "-c", "%a:%U:%G", path)
		if actual != expected {
			t.Fatalf("%s state = %q, want %q", path, actual, expected)
		}
	}
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("condition was not satisfied before timeout")
}

func run(t *testing.T, name string, arguments ...string) {
	t.Helper()
	command := exec.Command(name, arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, arguments, err, output)
	}
}

func runOK(name string, arguments ...string) bool {
	return exec.Command(name, arguments...).Run() == nil
}

func commandOutput(t *testing.T, dockerArguments ...string) string {
	t.Helper()
	output, err := exec.Command("docker", dockerArguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %v: %v\n%s", dockerArguments, err, output)
	}
	return strings.TrimSpace(string(output))
}

func requiredEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func requiredDirectory(t *testing.T, name string) string {
	t.Helper()
	value := requiredEnvironment(t, name)
	absolute, err := filepath.Abs(value)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.IsDir() {
		t.Fatalf("%s must name a directory: %v", name, err)
	}
	return absolute
}
