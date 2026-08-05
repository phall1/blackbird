package main

import (
	"fmt"
	"os"

	"github.com/phall1/blackbird/internal/transport/contracts"
)

func main() {
	document, err := contracts.ProductOpenAPI31()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "generate Blackbird OpenAPI: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(document); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "write Blackbird OpenAPI: %v\n", err)
		os.Exit(1)
	}
}
