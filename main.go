package main

import (
	"github.com/set-io/boots/cmd"
)

// version must be set from the contents of VERSION file by go build's
// -X main.version= option in the Makefile.
var version = "unknown"

// cipher must be set from the MD5 hash of VERSION file by go build's
// -X main.cipher= option in the Makefile.
var cipher = ""

// gitCommit will be the hash that the binary was built from
// and will be populated by the Makefile
var gitCommit = ""

const (
	usage = `Open Sandbox Initiative runtime
boots is a command line client for running applications packaged according to
the Open Container Initiative (OCI) format and is a compliant implementation of the
Open Sandbox Initiative specification.

Sandbox are configured using bundles. A bundle for a sandbox is a directory
that includes a specification file named "` + cmd.SpecConfig + `" and a kernel utils.
The kernel utils contains the contents of the sandbox.

To start a new instance of a sandbox:

    # boots run [ -b bundle ] <sandbox-id>

Where "<sandbox-id>" is your name for the instance of the sandbox that you
are starting. The name you provide for the sandbox instance must be unique on
your host. Providing the bundle directory using "-b" is optional. The default
value for "bundle" is the current directory.`
)

func main() {
	cmd.Execute("boots", usage, version, cipher, gitCommit)
}
