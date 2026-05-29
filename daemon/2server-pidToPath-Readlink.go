//go:build linux || freebsd || solaris || illumos

package daemon

import (
	"fmt"
	"os"
)

// pidToPath returns the path of the executable that has the given PID.
func pidToPath(pid int) string {
	path, _ := os.Readlink(fmt.Sprintf("/proc/%d/"+pidPathFile, pid))
	return path
}
