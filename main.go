package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Port    int
	Workers int
	Timeout time.Duration
	File    string
	Output  string
	Verbose bool
	Retries int
	Quiet   bool
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

func probe(ctx context.Context, domain string, port int, timeout time.Duration, retries int) Result {
	ips, err := resolveIPs(ctx, domain, timeout)
	if err != nil {
		return Result{Domain: domain, IP: "?", Allowed: false, Error: err.Error()}
	}

	var lastErr error
	lastIP := "?"
	for _, ip := range ips {
		addr := fmt.Sprintf("%s:%d", ip, port)
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
	flag.BoolVar(&cfg.Quiet, "q", false, "Quiet mode (hide start/end scan logs)")
	flag.Parse()

	if cfg.File == "" {
		logf(logColorize, "ERR", "usage: sniper -f domains.txt [options]")
		flag.PrintDefaults()
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
				r := probe(ctx, domain, cfg.Port, cfg.Timeout, cfg.Retries)

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

	var total int64
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		if d := scanner.Text(); d != "" {
			total++
			jobs <- d
		}
	}
	scanErr := scanner.Err()
	close(jobs)
	wg.Wait()
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
