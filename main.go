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
	Workers    int
	Timeout    time.Duration
	File       string
	Output     string
	Verbose    bool
	Retries    int
	Quiet      bool
	IPv6       bool
	TargetIP   string
	TargetFile string
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

func printUsage(colorize bool) {
	logf(colorize, "ERR", "usage: sniper -f domains.txt [options]")
	logf(colorize, "ERR", "   or: sniper domain [options]")
	flag.PrintDefaults()
}

func splitCLIArgs(args []string) ([]string, []string) {
	valueFlags := map[string]struct{}{
		"f":           {},
		"port":        {},
		"workers":     {},
		"timeout":     {},
		"output":      {},
		"retries":     {},
		"target":      {},
		"target-file": {},
	}
	boolFlags := map[string]struct{}{
		"verbose": {},
		"ipv6":    {},
		"q":       {},
		"h":       {},
		"help":    {},
	}

	var flagArgs []string
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}

		flagArgs = append(flagArgs, arg)
		if strings.Contains(arg, "=") {
			continue
		}

		name := strings.TrimLeft(arg, "-")
		if _, ok := boolFlags[name]; ok {
			continue
		}
		if _, ok := valueFlags[name]; ok {
			if i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}

		// Preserve a following non-flag token for unknown flags so it does not get
		// misclassified as positional input before flag parsing reports the error.
		if i+1 < len(args) {
			next := args[i+1]
			if next == "-" || !strings.HasPrefix(next, "-") {
				i++
				flagArgs = append(flagArgs, next)
			}
		}
	}

	return flagArgs, positional
}

func normalizeIP(raw string) (net.IP, error) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", raw)
	}
	return ip, nil
}

func enqueueDomains(jobs chan<- string, filePath, singleDomain string) (int64, error) {
	if singleDomain != "" {
		jobs <- singleDomain
		return 1, nil
	}

	inFile, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("cannot open %s: %w", filePath, err)
	}
	defer inFile.Close()

	var total int64
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		if domain := strings.TrimSpace(scanner.Text()); domain != "" {
			total++
			jobs <- domain
		}
	}
	if err := scanner.Err(); err != nil {
		return total, fmt.Errorf("cannot read %s: %w", filePath, err)
	}
	return total, nil
}

func loadOverrideIPs(targetIP, targetFile string) ([]net.IP, error) {
	if targetIP != "" && targetFile != "" {
		return nil, fmt.Errorf("cannot use -target and -target-file together")
	}
	if targetIP == "" && targetFile == "" {
		return nil, nil
	}

	var ips []net.IP
	seen := make(map[string]struct{})
	addIP := func(raw string) error {
		ip, err := normalizeIP(raw)
		if err != nil {
			return err
		}
		ipStr := ip.String()
		if _, ok := seen[ipStr]; ok {
			return nil
		}
		seen[ipStr] = struct{}{}
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

func resolveIPs(ctx context.Context, domain string, timeout time.Duration, includeIPv6 bool) ([]net.IP, error) {
	resolver := &net.Resolver{}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	network := "ip4"
	if includeIPv6 {
		network = "ip"
	}

	addrs, err := resolver.LookupIP(lookupCtx, network, domain)
	if err != nil {
		return nil, fmt.Errorf("dns failed: %w", err)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("dns failed: no addresses returned")
	}
	return addrs, nil
}

func candidateIPs(ctx context.Context, domain string, timeout time.Duration, includeIPv6 bool, overrideIPs []net.IP) ([]net.IP, error) {
	if len(overrideIPs) > 0 {
		return overrideIPs, nil
	}
	return resolveIPs(ctx, domain, timeout, includeIPv6)
}

func probe(ctx context.Context, domain string, port int, timeout time.Duration, retries int, includeIPv6 bool, overrideIPs []net.IP) Result {
	ips, err := candidateIPs(ctx, domain, timeout, includeIPv6, overrideIPs)
	if err != nil {
		return Result{Domain: domain, IP: "?", Allowed: false, Error: err.Error()}
	}

	var lastErr error
	lastIP := "?"
	for _, ip := range ips {
		ipStr := ip.String()
		addr := net.JoinHostPort(ipStr, strconv.Itoa(port))
		lastIP = ipStr

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
				return Result{Domain: domain, IP: ipStr, Allowed: true, Latency: time.Since(start)}
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

func main() {
	cfg := Config{}
	logColorize := fileIsTerminal(os.Stderr)
	flag.StringVar(&cfg.File, "f", "", "Input file with domains (one per line)")
	flag.IntVar(&cfg.Port, "port", 443, "TLS port to probe")
	flag.IntVar(&cfg.Workers, "workers", 200, "Concurrent workers")
	flag.DurationVar(&cfg.Timeout, "timeout", 2*time.Second, "Per DNS/dial/handshake attempt timeout")
	flag.StringVar(&cfg.Output, "output", "", "Save results to file (default: stdout)")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Also print blocked domains")
	flag.IntVar(&cfg.Retries, "retries", 0, "Retries on failure")
	flag.BoolVar(&cfg.IPv6, "ipv6", false, "Include IPv6 in DNS lookup")
	flag.BoolVar(&cfg.Quiet, "q", false, "Quiet mode (hide start/end scan logs)")
	flag.StringVar(&cfg.TargetIP, "target", "", "Override DNS and probe this IP for every domain")
	flag.StringVar(&cfg.TargetFile, "target-file", "", "Override DNS and probe IPs from this file for every domain")
	flagArgs, positionalDomains := splitCLIArgs(os.Args[1:])
	flag.CommandLine.Parse(flagArgs)

	if len(positionalDomains) > 1 {
		logf(logColorize, "ERR", "only one positional domain is supported")
		os.Exit(1)
	}

	singleDomain := ""
	if len(positionalDomains) == 1 {
		singleDomain = strings.TrimSpace(positionalDomains[0])
	}

	if cfg.File != "" && singleDomain != "" {
		logf(logColorize, "ERR", "cannot use both -f and a positional domain")
		os.Exit(1)
	}

	if cfg.File == "" && singleDomain == "" {
		printUsage(logColorize)
		os.Exit(1)
	}

	overrideIPs, err := loadOverrideIPs(cfg.TargetIP, cfg.TargetFile)
	if err != nil {
		logf(logColorize, "ERR", "%v", err)
		os.Exit(1)
	}

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

	jobs := make(chan string, cfg.Workers*2)
	lines := make(chan string, cfg.Workers*4)
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
			for domain := range jobs {
				r := probe(ctx, domain, cfg.Port, cfg.Timeout, cfg.Retries, cfg.IPv6, overrideIPs)

				if r.Allowed {
					allowed.Add(1)
					writeLine("%-30s %-18s %s allowed", r.Domain, r.IP, formatLatency(r.Latency.Milliseconds(), outputColorize))
				} else {
					failed.Add(1)
					if cfg.Verbose {
						writeLine("%-30s %-18s %s blocked", r.Domain, r.IP, formatLatency(r.Latency.Milliseconds(), outputColorize))
					}
				}
			}
		}()
	}

	total, scanErr := enqueueDomains(jobs, cfg.File, singleDomain)
	close(jobs)
	wg.Wait()
	close(lines)
	writeWG.Wait()

	if scanErr != nil {
		cleanupOutput()
		logf(logColorize, "ERR", "%v", scanErr)
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
