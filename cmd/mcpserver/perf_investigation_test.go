package mcpserver

// Measurement harness for issue #4115 (MCP analysis-tool performance). It is
// an investigation tool, not a regression test: it is skipped unless
// KUBESCAPE_MCP_PERF=1, prints tables with -v, and asserts nothing about
// timing. Run:
//
//	KUBESCAPE_MCP_PERF=1 go test ./cmd/mcpserver -run TestPerfInvestigation -v -count=1
//
// Two measurement backends are used, and neither is a production cluster:
//
//   - fake: the client-go fake dynamic client with a reactor that sleeps a
//     fixed per-request latency. No HTTP, no client-side rate limiter.
//   - http: the real client-go dynamic client (REST, JSON, the client-side
//     token-bucket rate limiter) against an in-process httptest server on
//     loopback that sleeps a fixed per-request latency. It exercises the real
//     client code path but not a real kube-apiserver (no auth, no priority and
//     fairness, no etcd, no TLS, no network RTT variance).

// Baseline recorded against upstream/master 726ed5ca on darwin/amd64, go1.26.8,
// one machine, loopback only. Per-request latency is injected, so absolute
// times are illustrative; request counts are deterministic. Treat every
// timing as one machine's single sample, not a distribution, unless stated.
//
//	Area 1 (sequential Gets): analyze_vulnerability_exposure issues one Get
//	  per distinct scanned workload (not duplicated requests). Fake client:
//	  wall time grows linearly with N x per-request latency. Real client,
//	  10ms/req, N=50: default limiter (5 QPS, burst 10) 8.0s sequential vs 8.0s
//	  with 8 workers (single run); limiter raised to 100/200: 0.58s vs 0.08s
//	  (median of 5). Within these runs the client-side limiter was the
//	  significant factor; parallel Gets only helped once it was raised, which
//	  is a separate decision and was not evaluated against a real cluster.
//	Area 2 (duplicate calls): K identical concurrent calls issue K x the
//	  requests (9 per analyze_service_exposure, CRDs absent). This harness does
//	  not establish whether duplicates occur in real use; the fake client
//	  serializes calls, so only its request counts are meaningful, and the
//	  HTTP figures show duplicates sharing one client-side token bucket.
//	Area 3 (Gateway fallback): 6 failed LISTs per call when the CRDs are
//	  absent, 3 when installed, for both tools. A separate, manual, read-only
//	  check against a local single-node kind API server (not part of this
//	  harness) saw ~2ms per 404; that does not describe remote clusters.
//
// None of this is production evidence, and it does not by itself justify or
// rule out any change to the tools.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func skipUnlessPerf(t *testing.T) {
	t.Helper()
	if os.Getenv("KUBESCAPE_MCP_PERF") != "1" {
		t.Skip("set KUBESCAPE_MCP_PERF=1 to run the #4115 measurement harness")
	}
}

// apiTally counts Kubernetes API requests by "verb resource" and tracks the
// peak number of requests in flight at once.
type apiTally struct {
	mu          sync.Mutex
	byKind      map[string]int
	inflight    int32
	maxInflight int32
}

func newAPITally() *apiTally { return &apiTally{byKind: map[string]int{}} }

func (a *apiTally) enter(kind string, latency time.Duration) {
	cur := atomic.AddInt32(&a.inflight, 1)
	for {
		m := atomic.LoadInt32(&a.maxInflight)
		if cur <= m || atomic.CompareAndSwapInt32(&a.maxInflight, m, cur) {
			break
		}
	}
	a.mu.Lock()
	a.byKind[kind]++
	a.mu.Unlock()
	if latency > 0 {
		time.Sleep(latency)
	}
	atomic.AddInt32(&a.inflight, -1)
}

func (a *apiTally) total() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, c := range a.byKind {
		n += c
	}
	return n
}

func (a *apiTally) matching(substr string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for k, c := range a.byKind {
		if strings.Contains(k, substr) {
			n += c
		}
	}
	return n
}

func (a *apiTally) reset() {
	a.mu.Lock()
	a.byKind = map[string]int{}
	a.mu.Unlock()
	atomic.StoreInt32(&a.maxInflight, 0)
}

func percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := int(float64(len(s)-1) * p)
	return s[idx]
}

func perfListKinds() map[schema.GroupVersionResource]string {
	return map[schema.GroupVersionResource]string{
		networkPolicyGVR: "NetworkPolicyList",
		namespaceGVR:     "NamespaceList",
		{Group: "apps", Version: "v1", Resource: "deployments"}: "DeploymentList",
		{Group: "", Version: "v1", Resource: "pods"}:            "PodList",
		serviceGVR:           "ServiceList",
		ingressGVR:           "IngressList",
		httpRouteGVR:         "HTTPRouteList",
		grpcRouteGVR:         "GRPCRouteList",
		gatewayGVR:           "GatewayList",
		httpRouteGVRv1beta1:  "HTTPRouteList",
		grpcRouteGVRv1alpha2: "GRPCRouteList",
		gatewayGVRv1beta1:    "GatewayList",
	}
}

// perfFakeServer builds a server over the fake dynamic client with nWorkloads
// Deployments and one scanned VulnerabilityManifest each. Every request sleeps
// latency and is tallied. When gatewayAbsent is true, Gateway API lists return
// NotFound exactly as an API server without the CRDs does.
func perfFakeServer(t *testing.T, nWorkloads int, latency time.Duration, gatewayAbsent bool, tally *apiTally) *KubescapeMcpserver {
	t.Helper()
	var objs []runtime.Object
	var manifests []runtime.Object
	for i := 0; i < nWorkloads; i++ {
		name := fmt.Sprintf("web-%d", i)
		objs = append(objs, unstructuredDeployment("prod", name, map[string]any{"app": name}))
		manifests = append(manifests, vulnerabilityManifest("prod", name+"-m",
			fmt.Sprintf("wlid://cluster-test/namespace-prod/deployment-%s", name), criticalMatch("CVE-2024-1")))
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), perfListKinds(), objs...)
	dyn.PrependReactor("*", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		gvr := a.GetResource()
		tally.enter(a.GetVerb()+" "+gvr.Resource, latency)
		if gatewayAbsent && gvr.Group == "gateway.networking.k8s.io" {
			return true, nil, notFoundForGVR(gvr)
		}
		return false, nil, nil
	})
	storage := storagefake.NewClientset(manifests...)
	ks := &KubescapeMcpserver{
		s:         server.NewMCPServer("perf", "test", server.WithToolCapabilities(false), server.WithRecovery()),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn},
		ksClientInit: func() (spdxv1beta1.SpdxV1beta1Interface, error) {
			return storage.SpdxV1beta1(), nil
		},
	}
	createVulnerabilityExposureTools(ks)
	createServiceExposureTools(ks)
	return ks
}

func notFoundForGVR(gvr schema.GroupVersionResource) error {
	return &statusNotFound{gvr: gvr}
}

type statusNotFound struct{ gvr schema.GroupVersionResource }

func (e *statusNotFound) Error() string { return "the server could not find the requested resource" }
func (e *statusNotFound) Status() metav1.Status {
	return metav1.Status{Status: metav1.StatusFailure, Reason: metav1.StatusReasonNotFound, Code: http.StatusNotFound,
		Details: &metav1.StatusDetails{Group: e.gvr.Group, Kind: e.gvr.Resource}}
}

func callTool(_ context.Context, t *testing.T, ks *KubescapeMcpserver, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res := registeredToolResult(t, dispatchRegisteredTool(t, ks, tool, args))
	require.False(t, res.IsError, toolResultText(t, res))
	return res
}

// httpAPI is a loopback stand-in for a kube-apiserver serving just enough of
// the API for the exposure tools.
type httpAPI struct {
	srv     *httptest.Server
	tally   *apiTally
	latency time.Duration
	gateway bool // true: Gateway API CRDs installed (empty lists); false: 404
}

func newHTTPAPI(latency time.Duration, gatewayInstalled bool) *httpAPI {
	h := &httpAPI{tally: newAPITally(), latency: latency, gateway: gatewayInstalled}
	h.srv = httptest.NewServer(http.HandlerFunc(h.serve))
	return h
}

func (h *httpAPI) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	kind := r.Method + " " + p
	switch {
	case strings.Contains(p, "/deployments/"):
		kind = "GET deployments"
	case strings.Contains(p, "gateway.networking.k8s.io"):
		parts := strings.Split(strings.Trim(p, "/"), "/")
		kind = "LIST gateway-api " + parts[len(parts)-1] + " @" + parts[2]
	default:
		parts := strings.Split(strings.Trim(p, "/"), "/")
		kind = "LIST " + parts[len(parts)-1]
	}
	h.tally.enter(kind, h.latency)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.Contains(p, "/deployments/"):
		name := p[strings.LastIndex(p, "/")+1:]
		_ = json.NewEncoder(w).Encode(unstructuredDeployment("prod", name, map[string]any{"app": name}).Object)
	case strings.Contains(p, "gateway.networking.k8s.io") && !h.gateway:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
			Status: metav1.StatusFailure, Reason: metav1.StatusReasonNotFound, Code: 404, Message: "the server could not find the requested resource"})
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "List", "metadata": map[string]any{}, "items": []any{}})
	}
}

func (h *httpAPI) dyn(t *testing.T, qps float32, burst int) dynamic.Interface {
	t.Helper()
	c, err := dynamic.NewForConfig(&rest.Config{Host: h.srv.URL, QPS: qps, Burst: burst})
	require.NoError(t, err)
	return c
}

func perfHTTPServer(t *testing.T, api *httpAPI, nWorkloads int, qps float32, burst int) *KubescapeMcpserver {
	t.Helper()
	var manifests []runtime.Object
	for i := 0; i < nWorkloads; i++ {
		name := fmt.Sprintf("web-%d", i)
		manifests = append(manifests, vulnerabilityManifest("prod", name+"-m",
			fmt.Sprintf("wlid://cluster-test/namespace-prod/deployment-%s", name), criticalMatch("CVE-2024-1")))
	}
	storage := storagefake.NewClientset(manifests...)
	ks := &KubescapeMcpserver{
		s:         server.NewMCPServer("perf", "test", server.WithToolCapabilities(false), server.WithRecovery()),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: api.dyn(t, qps, burst)},
		ksClientInit: func() (spdxv1beta1.SpdxV1beta1Interface, error) {
			return storage.SpdxV1beta1(), nil
		},
	}
	createVulnerabilityExposureTools(ks)
	createServiceExposureTools(ks)
	return ks
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000) }

// Area 1a: how much of analyze_vulnerability_exposure's wall time is the
// sequential Get loop, as a function of workload count and per-request
// latency (fake client, no client-side rate limiter).
func TestPerfInvestigation_SequentialGets_Fake(t *testing.T) {
	skipUnlessPerf(t)
	fmt.Println("\n== Area 1a: analyze_vulnerability_exposure, fake client, gateway CRDs absent ==")
	fmt.Printf("%-6s %-9s %-5s %-10s %-10s %-10s %-6s %-6s %-9s\n", "N", "latency", "runs", "p50", "p95", "max", "GETs", "total", "maxInfl")
	for _, n := range []int{10, 50, 200} {
		for _, lat := range []time.Duration{0, 2 * time.Millisecond, 10 * time.Millisecond} {
			tally := newAPITally()
			ks := perfFakeServer(t, n, lat, true, tally)
			const runs = 7
			var ds []time.Duration
			for i := 0; i < runs; i++ {
				tally.reset()
				s := time.Now()
				callTool(context.Background(), t, ks, "analyze_vulnerability_exposure", map[string]any{})
				ds = append(ds, time.Since(s))
			}
			fmt.Printf("%-6d %-9s %-5d %-10s %-10s %-10s %-6d %-6d %-9d\n", n, lat, runs,
				ms(percentile(ds, 0.5)), ms(percentile(ds, 0.95)), ms(percentile(ds, 1)),
				tally.matching("get "), tally.total(), atomic.LoadInt32(&tally.maxInflight))
		}
	}
}

// Area 1b: the real client's rate limiter vs. the Get loop. Sequential Gets
// versus the same Gets on a bounded worker pool (errgroup limit 8, a
// measurement stand-in, not shipped code), at client-go's defaults
// (QPS 5, burst 10 -- what an unconfigured rest.Config gets) and with the
// limiter raised.
func TestPerfInvestigation_SequentialGets_RateLimiter(t *testing.T) {
	skipUnlessPerf(t)
	fmt.Println("\n== Area 1b: Get loop vs client-side rate limiter (real dynamic client, loopback, latency 10ms; median of 5, default limiter 1 run) ==")
	fmt.Printf("%-4s %-14s %-12s %-12s %-12s\n", "N", "limiter", "sequential", "parallel(8)", "speedup")
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	for _, n := range []int{10, 50} {
		for _, lim := range []struct {
			name  string
			qps   float32
			burst int
		}{{"default 5/10", 0, 0}, {"raised 100/200", 100, 200}} {
			run := func(parallel bool) time.Duration {
				api := newHTTPAPI(10*time.Millisecond, false)
				defer api.srv.Close()
				dyn := api.dyn(t, lim.qps, lim.burst)
				ctx := context.Background()
				s := time.Now()
				if !parallel {
					for i := 0; i < n; i++ {
						_, err := dyn.Resource(gvr).Namespace("prod").Get(ctx, fmt.Sprintf("web-%d", i), metav1.GetOptions{})
						require.NoError(t, err)
					}
				} else {
					var eg errgroup.Group
					eg.SetLimit(8)
					for i := 0; i < n; i++ {
						i := i
						eg.Go(func() error {
							_, err := dyn.Resource(gvr).Namespace("prod").Get(ctx, fmt.Sprintf("web-%d", i), metav1.GetOptions{})
							return err
						})
					}
					require.NoError(t, eg.Wait())
				}
				return time.Since(s)
			}
			// The default limiter is deterministic and slow, so it is run
			// once; the raised limiter is run several times.
			runs := 5
			if lim.qps == 0 {
				runs = 1
			}
			median := func(parallel bool) time.Duration {
				var ds []time.Duration
				for i := 0; i < runs; i++ {
					ds = append(ds, run(parallel))
				}
				return percentile(ds, 0.5)
			}
			seq, par := median(false), median(true)
			fmt.Printf("%-4d %-14s %-12s %-12s %-12.2fx\n", n, lim.name, ms(seq), ms(par), float64(seq)/float64(par))
		}
	}
}

// Area 2: identical concurrent calls. Every duplicate repeats every request.
func TestPerfInvestigation_DuplicateConcurrentCalls(t *testing.T) {
	skipUnlessPerf(t)
	fmt.Println("\n== Area 2: K identical concurrent calls (fake client, N=20 workloads, latency 10ms) ==")
	fmt.Println("   NOTE: the fake clientset serializes requests behind a mutex, so wall time here scales with K by construction; only the request counts are meaningful.")
	fmt.Printf("%-28s %-3s %-10s %-10s %-9s %-9s\n", "tool", "K", "wall", "per-call", "requests", "req/call")
	for _, tool := range []string{"analyze_service_exposure", "analyze_vulnerability_exposure"} {
		for _, k := range []int{1, 2, 4, 8} {
			tally := newAPITally()
			ks := perfFakeServer(t, 20, 10*time.Millisecond, true, tally)
			args := map[string]any{}
			if tool == "analyze_service_exposure" {
				args = map[string]any{"namespace": "prod"}
			}
			var wg sync.WaitGroup
			durs := make([]time.Duration, k)
			s := time.Now()
			for i := 0; i < k; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					cs := time.Now()
					callTool(context.Background(), t, ks, tool, args)
					durs[i] = time.Since(cs)
				}(i)
			}
			wg.Wait()
			wall := time.Since(s)
			fmt.Printf("%-28s %-3d %-10s %-10s %-9d %-9d\n", tool, k, ms(wall), ms(percentile(durs, 0.5)), tally.total(), tally.total()/k)
		}
	}

	fmt.Println("\n-- same, real dynamic client over loopback with default limiter (5/10), service exposure, latency 10ms --")
	fmt.Printf("%-3s %-10s %-10s %-9s\n", "K", "wall", "p50 call", "requests")
	for _, k := range []int{1, 2, 4} {
		api := newHTTPAPI(10*time.Millisecond, false)
		ks := perfHTTPServer(t, api, 0, 0, 0)
		var wg sync.WaitGroup
		durs := make([]time.Duration, k)
		s := time.Now()
		for i := 0; i < k; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				cs := time.Now()
				callTool(context.Background(), t, ks, "analyze_service_exposure", map[string]any{"namespace": "prod"})
				durs[i] = time.Since(cs)
			}(i)
		}
		wg.Wait()
		fmt.Printf("%-3d %-10s %-10s %-9d\n", k, ms(time.Since(s)), ms(percentile(durs, 0.5)), api.tally.total())
		api.srv.Close()
	}
}

// Area 3: requests spent probing for absent Gateway API CRDs, and what that
// costs in wall time with and without the CRDs installed.
func TestPerfInvestigation_GatewayFallback(t *testing.T) {
	skipUnlessPerf(t)
	fmt.Println("\n== Area 3: Gateway API requests per call (real dynamic client, loopback) ==")
	fmt.Printf("%-28s %-10s %-9s %-10s %-10s %-9s %-9s %-9s\n", "tool", "CRDs", "latency", "p50", "max", "total", "gateway", "gw-share")
	for _, tool := range []string{"analyze_service_exposure", "analyze_vulnerability_exposure"} {
		for _, installed := range []bool{false, true} {
			for _, lat := range []time.Duration{0, 10 * time.Millisecond} {
				api := newHTTPAPI(lat, installed)
				ks := perfHTTPServer(t, api, 5, 100, 200) // limiter raised: isolate request count from throttling
				args := map[string]any{"namespace": "prod"}
				if tool == "analyze_vulnerability_exposure" {
					args = map[string]any{}
				}
				const runs = 9
				var ds []time.Duration
				for i := 0; i < runs; i++ {
					api.tally.reset()
					s := time.Now()
					callTool(context.Background(), t, ks, tool, args)
					ds = append(ds, time.Since(s))
				}
				gw := api.tally.matching("gateway-api")
				tot := api.tally.total()
				crd := "absent"
				if installed {
					crd = "installed"
				}
				fmt.Printf("%-28s %-10s %-9s %-10s %-10s %-9d %-9d %-8.0f%%\n", tool, crd, lat,
					ms(percentile(ds, 0.5)), ms(percentile(ds, 1)), tot, gw, 100*float64(gw)/float64(tot))
				if lat == 10*time.Millisecond && tool == "analyze_service_exposure" && !installed {
					api.tally.mu.Lock()
					fmt.Printf("   per-endpoint (one call): %v\n", api.tally.byKind)
					api.tally.mu.Unlock()
				}
				api.srv.Close()
			}
		}
	}
}
