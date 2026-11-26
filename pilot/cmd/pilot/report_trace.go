package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Opt-in capture of application messages for a synthetic report. Provisioning and witness
// exchange stay inside the Wasmer guests and are outside the public transcript.
func reportTrace(start time.Time, item M) error {
	dir := os.Getenv("HTTP6_PILOT_REPORT_DIR")
	if dir == "" {
		return nil
	}
	item["startedMicros"] = start.UnixMicro()
	item["finishedMicros"] = time.Now().UnixMicro()
	path := filepath.Join(dir, fmt.Sprintf("%020d-%s.json", start.UnixMicro(), nonce()))
	return artifact(path, item)
}
