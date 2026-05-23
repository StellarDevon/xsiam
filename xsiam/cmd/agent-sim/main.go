// agent-sim simulates N endpoint agents posting lifecycle events to the XSIAM
// internal server (default :18090/internal/agent/event).
//
// Each agent runs its own goroutine and goes through these phases:
//
//	startup delay (jitter) → connect → heartbeat loop → disconnect
//	          ↑___________random back-off retry______________|
//
// Usage:
//
//	go run ./cmd/agent-sim                          # defaults
//	go run ./cmd/agent-sim -n 5 -url http://localhost:18090
//	go run ./cmd/agent-sim -n 10 -hb 15s -session 2m
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ── CLI flags ─────────────────────────────────────────────────────────────────

var (
	flagN        = flag.Int("n", 6, "number of simulated agents")
	flagURL      = flag.String("url", "http://localhost:18090", "internal server base URL")
	flagHB       = flag.Duration("hb", 20*time.Second, "heartbeat interval")
	flagSession  = flag.Duration("session", 90*time.Second, "how long each agent stays connected before disconnecting")
	flagJitter   = flag.Duration("jitter", 15*time.Second, "max random startup delay between agents")
	flagBackoff  = flag.Duration("backoff-min", 5*time.Second, "min reconnect backoff")
	flagBackoffX = flag.Duration("backoff-max", 40*time.Second, "max reconnect backoff")
	flagVerbose  = flag.Bool("v", false, "verbose logging")
)

// ── Agent event payload ───────────────────────────────────────────────────────

type agentEvent struct {
	AgentID      string    `json:"agent_id"`
	Event        string    `json:"event"`
	Hostname     string    `json:"hostname,omitempty"`
	IPAddresses  []string  `json:"ip_addresses,omitempty"`
	OSType       string    `json:"os_type,omitempty"`
	OSVersion    string    `json:"os_version,omitempty"`
	AgentVersion string    `json:"agent_version,omitempty"`
	PolicyID     string    `json:"policy_id,omitempty"`
	TenantID     string    `json:"tenant_id,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// ── Simulated agent profiles ──────────────────────────────────────────────────

type profile struct {
	agentID      string
	hostname     string
	ip           string
	osType       string
	osVersion    string
	agentVersion string
}

var agentProfiles = []profile{
	{"agent-00001", "WIN-LAPTOP-CEO", "10.0.1.101", "windows", "11", "7.4.2"},
	{"agent-00002", "WIN-WS-FIN-01", "10.0.1.102", "windows", "10", "7.4.1"},
	{"agent-00003", "LNX-SRV-DB-01", "10.0.2.50", "linux", "Ubuntu 22.04", "7.4.2"},
	{"agent-00004", "LNX-SRV-WEB-02", "10.0.2.51", "linux", "CentOS 7", "7.3.9"},
	{"agent-00005", "MAC-DEV-JDOE", "10.0.3.201", "macos", "14.4", "7.4.2"},
	{"agent-00006", "WIN-WS-HR-03", "10.0.1.115", "windows", "11", "7.4.0"},
	{"agent-00007", "LNX-BASTION-01", "10.0.0.10", "linux", "Debian 12", "7.4.2"},
	{"agent-00008", "WIN-DC-PROD-01", "10.0.0.5", "windows", "Server 2022", "7.4.2"},
}

// ── HTTP client ───────────────────────────────────────────────────────────────

var client = &http.Client{Timeout: 8 * time.Second}

func postEvent(baseURL string, ev agentEvent) error {
	body, _ := json.Marshal(ev)
	resp, err := client.Post(baseURL+"/internal/agent/event", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// ── Agent loop ────────────────────────────────────────────────────────────────

func runAgent(p profile, baseURL string, wg *sync.WaitGroup, stop <-chan struct{}) {
	defer wg.Done()
	logger := log.New(os.Stdout, fmt.Sprintf("[%s] ", p.agentID), log.Ltime)

	// Random startup jitter so agents don't all connect at once
	jitter := time.Duration(rand.Int63n(int64(*flagJitter)))
	select {
	case <-time.After(jitter):
	case <-stop:
		return
	}

	for {
		// ── Connect ───────────────────────────────────────────────────────
		ev := agentEvent{
			AgentID:      p.agentID,
			Event:        "connect",
			Hostname:     p.hostname,
			IPAddresses:  []string{p.ip},
			OSType:       p.osType,
			OSVersion:    p.osVersion,
			AgentVersion: p.agentVersion,
			PolicyID:     "default",
			TenantID:     "default",
			Timestamp:    time.Now(),
		}
		if err := postEvent(baseURL, ev); err != nil {
			logger.Printf("connect error: %v — retrying after backoff", err)
		} else {
			logger.Printf("CONNECT  hostname=%s os=%s/%s ver=%s", p.hostname, p.osType, p.osVersion, p.agentVersion)
		}

		// ── Heartbeat loop until session expires or stop ──────────────────
		sessionEnd := time.Now().Add(*flagSession + time.Duration(rand.Int63n(int64(*flagSession/2))))
		hbTicker := time.NewTicker(*flagHB)
	heartbeatLoop:
		for {
			select {
			case <-stop:
				hbTicker.Stop()
				// Send disconnect before exit
				_ = postEvent(baseURL, agentEvent{
					AgentID:   p.agentID,
					Event:     "disconnect",
					Timestamp: time.Now(),
				})
				logger.Printf("DISCONNECT (shutdown)")
				return

			case t := <-hbTicker.C:
				if t.After(sessionEnd) {
					hbTicker.Stop()
					break heartbeatLoop
				}
				hbEv := agentEvent{
					AgentID:   p.agentID,
					Event:     "heartbeat",
					Timestamp: t,
				}
				if err := postEvent(baseURL, hbEv); err != nil {
					if *flagVerbose {
						logger.Printf("heartbeat error: %v", err)
					}
				} else if *flagVerbose {
					logger.Printf("heartbeat")
				}
			}
		}

		// ── Disconnect ────────────────────────────────────────────────────
		_ = postEvent(baseURL, agentEvent{
			AgentID:   p.agentID,
			Event:     "disconnect",
			Timestamp: time.Now(),
		})
		logger.Printf("DISCONNECT (session ended, reconnecting after backoff)")

		// ── Random back-off before reconnect ──────────────────────────────
		span := int64(*flagBackoffX - *flagBackoff)
		backoff := *flagBackoff + time.Duration(rand.Int63n(span))
		logger.Printf("back-off  %v", backoff.Round(time.Second))
		select {
		case <-time.After(backoff):
		case <-stop:
			return
		}
	}
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano()) //nolint:staticcheck

	n := *flagN
	if n > len(agentProfiles) {
		n = len(agentProfiles)
	}
	profiles := agentProfiles[:n]

	fmt.Printf("\nxsiam agent-sim\n")
	fmt.Printf("  agents   : %d\n", n)
	fmt.Printf("  target   : %s/internal/agent/event\n", *flagURL)
	fmt.Printf("  heartbeat: %v\n", *flagHB)
	fmt.Printf("  session  : %v (±50%%)\n", *flagSession)
	fmt.Printf("  backoff  : %v–%v\n\n", *flagBackoff, *flagBackoffX)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, p := range profiles {
		wg.Add(1)
		go runAgent(p, *flagURL, &wg, stop)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\nstopping agents…")
	close(stop)
	wg.Wait()
	fmt.Println("done.")
}
