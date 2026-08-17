// Command spiffe-ad-broker exchanges a workload's SPIFFE SVID for a
// certificate that Active Directory will accept for PKINIT.
//
// Nothing is wired up yet. The entrypoint exists so the module has a real
// shape, and it refuses rather than starting a server that would accept
// connections and do nothing useful with them.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "spiffe-ad-broker: not implemented yet — see docs/DESIGN.md")
	os.Exit(1)
}
