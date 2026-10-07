package relay

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/remote-relay/relay/internal/proto"
	"github.com/remote-relay/relay/internal/transport"
)

type RegisteredAgent struct {
	Target           string
	Fingerprint      string
	RawPubKey        []byte
	DefaultDest      string
	AllowDest        []string
	PermittedTargets []string
	ControlConn      transport.Conn
	mu               sync.Mutex
	graceTimer       *time.Timer
	registeredAt     time.Time
	// controlRead is true while runAgentControlLoop is blocked in ReadFrame.
	// CreateBind must not clear the conn deadline during that read.
	controlRead bool
}

func (a *RegisteredAgent) IsConnected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ControlConn != nil
}

// noteControlRead records whether this conn is inside the control loop's ReadFrame.
// The loop sets it true before arming the idle deadline and false only after that read returns.
func (a *RegisteredAgent) noteControlRead(conn transport.Conn, active bool) {
	a.mu.Lock()
	if a.ControlConn == conn {
		a.controlRead = active
	}
	a.mu.Unlock()
}

type safeConn struct {
	transport.Conn
	writeMu sync.Mutex
}

func newSafeConn(c transport.Conn) transport.Conn {
	if sc, ok := c.(*safeConn); ok {
		return sc
	}
	return &safeConn{Conn: c}
}

func (s *safeConn) WriteFrame(f proto.Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.Conn.WriteFrame(f)
}

type PendingBind struct {
	BindID      string
	Target      string
	Destination string
	AgentPipe   *memoryPipeConn
	ClientPipe  *memoryPipeConn
	ReadyCh     chan struct{}
	Err         error
	mu          sync.Mutex
}

type AgentRegistry struct {
	mu           sync.RWMutex
	targets      map[string]*RegisteredAgent
	pendingBinds map[string]*PendingBind
}

func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		targets:      make(map[string]*RegisteredAgent),
		pendingBinds: make(map[string]*PendingBind),
	}
}

func (r *AgentRegistry) Register(target, fp string, rawPubKey []byte, dest string, allowDest, permittedTargets []string, controlConn transport.Conn) (*RegisteredAgent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	existing, exists := r.targets[target]
	if exists {
		if existing.Fingerprint != fp {
			return nil, fmt.Errorf("target %q already claimed by another key", target)
		}
		// Same key reconnecting! Stop grace timer if running.
		existing.mu.Lock()
		if existing.graceTimer != nil {
			existing.graceTimer.Stop()
			existing.graceTimer = nil
		}
		if existing.ControlConn != nil && existing.ControlConn != controlConn {
			_ = existing.ControlConn.Close()
		}
		existing.ControlConn = controlConn
		existing.DefaultDest = dest
		existing.AllowDest = allowDest
		existing.PermittedTargets = permittedTargets
		existing.mu.Unlock()
		return existing, nil
	}

	agent := &RegisteredAgent{
		Target:           target,
		Fingerprint:      fp,
		RawPubKey:        rawPubKey,
		DefaultDest:      dest,
		AllowDest:        allowDest,
		PermittedTargets: permittedTargets,
		ControlConn:      controlConn,
		registeredAt:     time.Now(),
	}
	r.targets[target] = agent
	return agent, nil
}

func (r *AgentRegistry) OnControlDisconnect(target string, holdTimeout time.Duration, controlConn transport.Conn) {
	r.mu.Lock()
	agent, ok := r.targets[target]
	if !ok {
		r.mu.Unlock()
		return
	}
	agent.mu.Lock()
	if controlConn != nil && agent.ControlConn != controlConn {
		// Already replaced by a newer connection
		agent.mu.Unlock()
		r.mu.Unlock()
		return
	}
	agent.ControlConn = nil
	if holdTimeout <= 0 {
		holdTimeout = 15 * time.Second
	}
	agent.graceTimer = time.AfterFunc(holdTimeout, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		curr, exists := r.targets[target]
		if exists && curr == agent {
			agent.mu.Lock()
			if agent.ControlConn == nil {
				delete(r.targets, target)
			}
			agent.mu.Unlock()
		}
	})
	agent.mu.Unlock()
	r.mu.Unlock()
}

func (r *AgentRegistry) CreateBind(target, dest, clientIP string, clientAddr net.Addr) (*PendingBind, *memoryPipeConn, error) {
	r.mu.Lock()
	agent, ok := r.targets[target]
	if !ok {
		r.mu.Unlock()
		return nil, nil, fmt.Errorf("target %q not registered", target)
	}
	agent.mu.Lock()
	ctrl := agent.ControlConn
	if ctrl == nil {
		agent.mu.Unlock()
		r.mu.Unlock()
		return nil, nil, fmt.Errorf("agent for target %q is currently disconnected", target)
	}

	actualDest := dest
	if actualDest == "" {
		actualDest = agent.DefaultDest
	}

	var idBytes [16]byte
	_, _ = rand.Read(idBytes[:])
	bindID := hex.EncodeToString(idBytes[:])

	clientPipe, agentPipe := newMemoryPipePair(clientAddr, ctrl.RemoteAddr())

	pb := &PendingBind{
		BindID:      bindID,
		Target:      target,
		Destination: actualDest,
		AgentPipe:   agentPipe,
		ClientPipe:  clientPipe,
		ReadyCh:     make(chan struct{}),
	}
	r.pendingBinds[bindID] = pb
	agent.mu.Unlock()
	r.mu.Unlock()

	bindMsg := proto.AgentBind{
		V:           1,
		BindID:      bindID,
		Target:      target,
		Destination: actualDest,
		ClientIP:    clientIP,
	}
	frame, err := proto.MarshalFrame(proto.TypeAgentBind, bindMsg)
	if err != nil {
		r.RemoveBind(bindID)
		_ = clientPipe.Close()
		_ = agentPipe.Close()
		return nil, nil, err
	}

	agent.mu.Lock()
	if agent.ControlConn == nil {
		agent.mu.Unlock()
		r.RemoveBind(bindID)
		_ = clientPipe.Close()
		_ = agentPipe.Close()
		return nil, nil, fmt.Errorf("agent control connection lost")
	}
	// A blocked control read already has a 2×heartbeat deadline. Replacing it
	// and then clearing it with a zero deadline cancels that idle timeout, so
	// the agent stays healthy forever after a bind. Touch the deadline only
	// between reads, and clear just that write bound.
	if !agent.controlRead {
		_ = agent.ControlConn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	err = agent.ControlConn.WriteFrame(frame)
	if !agent.controlRead && agent.ControlConn != nil {
		_ = agent.ControlConn.SetDeadline(time.Time{})
	}
	agent.mu.Unlock()

	if err != nil {
		r.RemoveBind(bindID)
		_ = clientPipe.Close()
		_ = agentPipe.Close()
		return nil, nil, fmt.Errorf("failed to send bind request to agent: %w", err)
	}

	return pb, clientPipe, nil
}

func (r *AgentRegistry) CompleteBind(bindID string) (*memoryPipeConn, error) {
	r.mu.Lock()
	pb, ok := r.pendingBinds[bindID]
	if !ok {
		r.mu.Unlock()
		return nil, fmt.Errorf("bind %q not found or expired", bindID)
	}
	delete(r.pendingBinds, bindID)
	r.mu.Unlock()

	pb.mu.Lock()
	close(pb.ReadyCh)
	pipe := pb.AgentPipe
	pb.mu.Unlock()

	return pipe, nil
}

func (r *AgentRegistry) FailBind(bindID string, err error) {
	r.mu.Lock()
	pb, ok := r.pendingBinds[bindID]
	if ok {
		delete(r.pendingBinds, bindID)
	}
	r.mu.Unlock()

	if pb != nil {
		pb.mu.Lock()
		pb.Err = err
		if pb.ClientPipe != nil {
			_ = pb.ClientPipe.Close()
		}
		if pb.AgentPipe != nil {
			_ = pb.AgentPipe.Close()
		}
		close(pb.ReadyCh)
		pb.mu.Unlock()
	}
}

func (r *AgentRegistry) RemoveBind(bindID string) {
	r.mu.Lock()
	delete(r.pendingBinds, bindID)
	r.mu.Unlock()
}

func (r *AgentRegistry) TargetCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.targets)
}

func (r *AgentRegistry) GetTarget(target string) (*RegisteredAgent, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	agent, ok := r.targets[target]
	return agent, ok
}

func (r *AgentRegistry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, target := range r.targets {
		target.mu.Lock()
		if target.graceTimer != nil {
			target.graceTimer.Stop()
		}
		if target.ControlConn != nil {
			_ = target.ControlConn.Close()
		}
		target.mu.Unlock()
	}
	r.targets = make(map[string]*RegisteredAgent)

	for _, pb := range r.pendingBinds {
		pb.mu.Lock()
		if pb.ClientPipe != nil {
			_ = pb.ClientPipe.Close()
		}
		if pb.AgentPipe != nil {
			_ = pb.AgentPipe.Close()
		}
		pb.mu.Unlock()
	}
	r.pendingBinds = make(map[string]*PendingBind)
}

type memoryPipeConn struct {
	r         *io.PipeReader
	w         *io.PipeWriter
	local     net.Addr
	remote    net.Addr
	closeOnce sync.Once
}

func (p *memoryPipeConn) Read(b []byte) (n int, err error) {
	return p.r.Read(b)
}

func (p *memoryPipeConn) Write(b []byte) (n int, err error) {
	return p.w.Write(b)
}

func (p *memoryPipeConn) Close() error {
	p.closeOnce.Do(func() {
		_ = p.r.Close()
		_ = p.w.Close()
	})
	return nil
}

func (p *memoryPipeConn) CloseWrite() error {
	return p.w.Close()
}

func (p *memoryPipeConn) LocalAddr() net.Addr                { return p.local }
func (p *memoryPipeConn) RemoteAddr() net.Addr               { return p.remote }
func (p *memoryPipeConn) SetDeadline(t time.Time) error      { return nil }
func (p *memoryPipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *memoryPipeConn) SetWriteDeadline(t time.Time) error { return nil }

func newMemoryPipePair(clientAddr, agentAddr net.Addr) (*memoryPipeConn, *memoryPipeConn) {
	c2aR, c2aW := io.Pipe()
	a2cR, a2cW := io.Pipe()
	clientConn := &memoryPipeConn{
		r:      a2cR,
		w:      c2aW,
		local:  clientAddr,
		remote: agentAddr,
	}
	agentConn := &memoryPipeConn{
		r:      c2aR,
		w:      a2cW,
		local:  agentAddr,
		remote: clientAddr,
	}
	return clientConn, agentConn
}
