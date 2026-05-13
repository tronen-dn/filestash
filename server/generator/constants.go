//go:build ignore

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	// Prefer BUILD_REF from the environment so Docker / CI builds without a
	// .git directory can still bake in a commit SHA. Fall back to git for
	// developer builds run from a checkout.
	ref := strings.TrimSpace(os.Getenv("BUILD_REF"))
	if ref == "" {
		cmd, b := exec.Command("git", "rev-parse", "HEAD"), new(strings.Builder)
		cmd.Stdout = b
		cmd.Run()
		ref = strings.TrimSpace(b.String())
	}

	f, err := os.OpenFile("../common/constants_generated.go", os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
		return
	}
	f.Write([]byte(fmt.Sprintf(`
package common

func init() {
    BUILD_REF = "%s"
    BUILD_DATE = "%s"
}
	`, ref, time.Now().Format("20060102"))))
	f.Close()
}
