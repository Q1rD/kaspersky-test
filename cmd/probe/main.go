// probe provides healthchecks and permission checks without a runtime shell.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) == 3 && (os.Args[1] == "read" || os.Args[1] == "write") {
		var err error
		if os.Args[1] == "read" {
			_, err = os.ReadFile(os.Args[2])
		} else {
			err = os.WriteFile(os.Args[2], []byte("permission-probe\n"), 0600)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	client := http.Client{Timeout: 3 * time.Second}
	r, err := client.Get(os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		os.Exit(1)
	}
}
