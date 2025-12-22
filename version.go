package main

import (
	"fmt"
	"runtime"
)

var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

func printVersion() {
	fmt.Printf("Fastls MITM Proxy\n")
	fmt.Printf("Version:     %s\n", version)
	fmt.Printf("Build Time:  %s\n", buildTime)
	fmt.Printf("Git Commit:  %s\n", gitCommit)
	fmt.Printf("Go Version:  %s\n", runtime.Version())
	fmt.Printf("Platform:    %s\n", runtime.GOOS)
	fmt.Printf("Architecture: %s\n", runtime.GOARCH)
	fmt.Printf("CPU Cores:   %d\n", runtime.NumCPU())
}
