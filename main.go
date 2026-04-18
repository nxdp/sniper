package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Port       int
	Ports      string
	Workers    int
	Timeout    time.Duration
	File       string
	Output     string
	Verbose    bool
	Retries    int
	Quiet      bool
	TargetIP   string
	TargetFile string
}

type Job struct {
	Domain string
	Port   int
}

type portOutcome struct {
	Allowed bool
	Latency time.Duration
	IP      string
}

type Result struct {
	Domain  string
	IP      string
	Latency time.Duration
	Allowed bool
	Error   string
}

var (
	allowed atomic.Int64
	failed  atomic.Int64
)

func logf(colorize bool, level string, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", formatLogLevel(level, colorize), fmt.Sprintf(format, args...))
}

func formatLogLevel(level string, colorize bool) string {
	tag := "[" + level + "]"
	if !colorize {
		return tag
	}

	switch level {
	case "INFO":
		return "\033[32m" + tag + "\033[0m"
	case "WARN":
		return "\033[33m" + tag + "\033[0m"
	case "ERR":
		return "\033[31m" + tag + "\033[0m"
	default:
		return tag
	}
}

func formatLatency(latencyMs int64, colorize bool) string {
	latency := fmt.Sprintf("%dms", latencyMs)
	if !colorize {
		return latency
	}

	switch {
	case latencyMs <= 2000:
		return "\033[32m" + latency + "\033[0m"
	case latencyMs <= 6000:
		return "\033[33m" + latency + "\033[0m"
	default:
		return "\033[31m" + latency + "\033[0m"
	}
}

func fileIsTerminal(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func normalizeIP(raw string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", fmt.Errorf("invalid IP %q", raw)
	}
	return ip.String(), nil
}

func loadOverrideIPs(targetIP, targetFile string) ([]string, error) {
	if targetIP != "" && targetFile != "" {
		return nil, fmt.Errorf("cannot use -target and -target-file together")
	}
	if targetIP == "" && targetFile == "" {
		return nil, nil
	}

	var ips []string
	seen := make(map[string]struct{})
	addIP := func(raw string) error {
		ip, err := normalizeIP(raw)
		if err != nil {
			return err
		}
		if _, ok := seen[ip]; ok {
			return nil
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
		return nil
	}

	if targetIP != "" {
		if err := addIP(targetIP); err != nil {
			return nil, fmt.Errorf("invalid -target: %w", err)
		}
		return ips, nil
	}

	inFile, err := os.Open(targetFile)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", targetFile, err)
	}
	defer inFile.Close()

	scanner := bufio.NewScanner(inFile)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if err := addIP(line); err != nil {
			return nil, fmt.Errorf("invalid IP in %s at line %d: %w", targetFile, lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", targetFile, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs found in %s", targetFile)
	}
	return ips, nil
}

func parsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("no ports specified")
	}
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", p)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port: %d", n)
		}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports specified")
	}
	return ports, nil
}

// resolvePorts uses -ports when non-empty; otherwise the single -port value (backward compatible).
func resolvePorts(portsFlag string, legacyPort int) ([]int, error) {
	if strings.TrimSpace(portsFlag) != "" {
		return parsePorts(portsFlag)
	}
	if legacyPort < 1 || legacyPort > 65535 {
		return nil, fmt.Errorf("invalid port: %d", legacyPort)
	}
	return []int{legacyPort}, nil
}

func resolveIPs(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	resolver := &net.Resolver{}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addrs, err := resolver.LookupHost(lookupCtx, domain)
	if err != nil {
		return nil, fmt.Errorf("dns failed: %w", err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("dns failed: no addresses returned")
	}
	return addrs, nil
}

func candidateIPs(ctx context.Context, domain string, timeout time.Duration, overrideIPs []string) ([]string, error) {
	if len(overrideIPs) > 0 {
		return overrideIPs, nil
	}
	return resolveIPs(ctx, domain, timeout)
}

func probe(ctx context.Context, domain string, port int, timeout time.Duration, retries int, overrideIPs []string) Result {
	ips, err := candidateIPs(ctx, domain, timeout, overrideIPs)
	if err != nil {
		return Result{Domain: domain, IP: "?", Allowed: false, Error: err.Error()}
	}

	var lastErr error
	lastIP := "?"
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		lastIP = ip

		for i := 0; i <= retries; i++ {
			if ctx.Err() != nil {
				return Result{Domain: domain, IP: lastIP, Allowed: false, Error: "cancelled"}
			}

			// TCP dial with context timeout
			dialCtx, cancel := context.WithTimeout(ctx, timeout)
			start := time.Now()
			rawConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
			cancel()

			if err != nil {
				lastErr = err
				if i < retries {
					select {
					case <-ctx.Done():
						return Result{Domain: domain, IP: lastIP, Allowed: false, Error: "cancelled"}
					case <-time.After(150 * time.Millisecond):
					}
				}
				continue
			}

			// TLS handshake with hard deadline
			tlsConn := tls.Client(rawConn, &tls.Config{
				ServerName:         domain,
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			})
			tlsConn.SetDeadline(time.Now().Add(timeout))
			err = tlsConn.Handshake()
			tlsConn.Close()

			if err == nil {
				return Result{Domain: domain, IP: ip, Allowed: true, Latency: time.Since(start)}
			}

			lastErr = err
			if i < retries {
				select {
				case <-ctx.Done():
					return Result{Domain: domain, IP: lastIP, Allowed: false, Error: "cancelled"}
				case <-time.After(150 * time.Millisecond):
				}
			}
		}
	}

	return Result{Domain: domain, IP: lastIP, Allowed: false, Error: lastErr.Error()}
}

func formatMark(ok bool, colorize bool) string {
	const (
		markOK   = "\u2713"
		markFail = "\u2717"
	)
	if !colorize {
		if ok {
			return markOK
		}
		return markFail
	}
	if ok {
		return "\033[32m" + markOK + "\033[0m"
	}
	return "\033[31m" + markFail + "\033[0m"
}

func pickDisplayIP(portOrder []int, perPort map[int]portOutcome) string {
	for _, p := range portOrder {
		if o, ok := perPort[p]; ok && o.IP != "" && o.IP != "?" {
			return o.IP
		}
	}
	return "?"
}

func maxAllowedLatency(perPort map[int]portOutcome, portOrder []int) (time.Duration, bool) {
	var max time.Duration
	var any bool
	for _, p := range portOrder {
		o, ok := perPort[p]
		if !ok || !o.Allowed {
			continue
		}
		any = true
		if o.Latency > max {
			max = o.Latency
		}
	}
	return max, any
}

func formatGroupedLine(domain string, probePorts []int, perPort map[int]portOutcome, colorize bool, verbose bool) string {
	if perPort == nil {
		perPort = map[int]portOutcome{}
	}
	anyAllowed := false
	for _, p := range probePorts {
		if o, ok := perPort[p]; ok && o.Allowed {
			anyAllowed = true
			break
		}
	}
	if !anyAllowed && !verbose {
		return ""
	}

	ip := pickDisplayIP(probePorts, perPort)
	latStr := "-"
	if maxLat, ok := maxAllowedLatency(perPort, probePorts); ok {
		latStr = formatLatency(maxLat.Milliseconds(), colorize)
	}

	var b strings.Builder
	for i, p := range probePorts {
		if i > 0 {
			b.WriteString("  ")
		}
		o, ok := perPort[p]
		allowed := ok && o.Allowed
		fmt.Fprintf(&b, "%d %s", p, formatMark(allowed, colorize))
	}

	return fmt.Sprintf("%-30s %-18s %s  %s", domain, ip, latStr, b.String())
}

func main() {
	cfg := Config{}
	logColorize := fileIsTerminal(os.Stderr)
	flag.StringVar(&cfg.File, "f", "", "Input file with domains (one per line)")
	flag.IntVar(&cfg.Port, "port", 443, "TLS port to probe (used when -ports is not set)")
	flag.StringVar(&cfg.Ports, "ports", "", "Comma-separated TLS ports (e.g. 443,2053); overrides -port when set")
	flag.IntVar(&cfg.Workers, "workers", 200, "Concurrent workers")
	flag.DurationVar(&cfg.Timeout, "timeout", 2*time.Second, "Per DNS/dial/handshake attempt timeout")
	flag.StringVar(&cfg.Output, "output", "", "Save results to file (default: stdout)")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Include domains where every port failed (hidden by default)")
	flag.IntVar(&cfg.Retries, "retries", 0, "Retries on failure")
	flag.BoolVar(&cfg.Quiet, "q", false, "Quiet mode (hide start/end scan logs)")
	flag.StringVar(&cfg.TargetIP, "target", "", "Override DNS and probe this IP for every domain")
	flag.StringVar(&cfg.TargetFile, "target-file", "", "Override DNS and probe IPs from this file for every domain")
	flag.Parse()

	if cfg.File == "" {
		logf(logColorize, "ERR", "usage: sniper -f domains.txt [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	ports, err := resolvePorts(cfg.Ports, cfg.Port)
	if err != nil {
		logf(logColorize, "ERR", "%v", err)
		os.Exit(1)
	}

	overrideIPs, err := loadOverrideIPs(cfg.TargetIP, cfg.TargetFile)
	if err != nil {
		logf(logColorize, "ERR", "%v", err)
		os.Exit(1)
	}

	inFile, err := os.Open(cfg.File)
	if err != nil {
		logf(logColorize, "ERR", "cannot open %s: %v", cfg.File, err)
		os.Exit(1)
	}
	defer inFile.Close()

	outWriter := bufio.NewWriter(os.Stdout)
	outputFile := os.Stdout
	var outFile *os.File
	if cfg.Output != "" {
		f, err := os.Create(cfg.Output)
		if err != nil {
			logf(logColorize, "ERR", "%v", err)
			os.Exit(1)
		}
		outFile = f
		outputFile = f
		outWriter = bufio.NewWriter(f)
	}
	outputColorize := fileIsTerminal(outputFile)

	cleanupOutput := func() {
		outWriter.Flush()
		if outFile != nil {
			outFile.Close()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make(chan Job, cfg.Workers*2)
	lines := make(chan string, cfg.Workers*4)
	var aggMu sync.Mutex
	aggregated := make(map[string]map[int]portOutcome)
	var wg sync.WaitGroup
	var writeWG sync.WaitGroup

	writeWG.Add(1)
	go func() {
		defer writeWG.Done()

		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case line, ok := <-lines:
				if !ok {
					outWriter.Flush()
					return
				}
				fmt.Fprintln(outWriter, line)
			case <-ticker.C:
				outWriter.Flush()
			}
		}
	}()

	writeLine := func(format string, args ...any) {
		lines <- fmt.Sprintf(format, args...)
	}

	if !cfg.Quiet {
		logf(logColorize, "INFO", "starting workers=%d timeout=%s", cfg.Workers, cfg.Timeout)
	}

	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				r := probe(ctx, job.Domain, job.Port, cfg.Timeout, cfg.Retries, overrideIPs)

				if r.Allowed {
					allowed.Add(1)
				} else {
					failed.Add(1)
				}

				aggMu.Lock()
				m := aggregated[job.Domain]
				if m == nil {
					m = make(map[int]portOutcome)
					aggregated[job.Domain] = m
				}
				m[job.Port] = portOutcome{
					Allowed: r.Allowed,
					Latency: r.Latency,
					IP:      r.IP,
				}
				aggMu.Unlock()
			}
		}()
	}

	var domainOrder []string
	seenDomain := make(map[string]struct{})
	var total int64
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}
		if _, ok := seenDomain[domain]; !ok {
			seenDomain[domain] = struct{}{}
			domainOrder = append(domainOrder, domain)
		}
		total += int64(len(ports))
		for _, port := range ports {
			jobs <- Job{Domain: domain, Port: port}
		}
	}
	scanErr := scanner.Err()
	close(jobs)
	wg.Wait()

	for _, domain := range domainOrder {
		line := formatGroupedLine(domain, ports, aggregated[domain], outputColorize, cfg.Verbose)
		if line != "" {
			writeLine("%s", line)
		}
	}

	close(lines)
	writeWG.Wait()

	if scanErr != nil {
		cleanupOutput()
		logf(logColorize, "ERR", "cannot read %s: %v", cfg.File, scanErr)
		os.Exit(1)
	}

	if !cfg.Quiet {
		level := "INFO"
		if allowed.Load() == 0 {
			level = "WARN"
		}
		logf(logColorize, level, "completed allowed=%d blocked=%d total=%d", allowed.Load(), failed.Load(), total)
	}
	cleanupOutput()
}
