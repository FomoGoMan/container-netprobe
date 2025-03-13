package helper

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
)

func IptablesSupportsCgroupPath() (bool, error) {

	cmd := exec.Command("iptables", "-m", "cgroup", "--help")
	cmd.Env = append(os.Environ(), "LANG=C")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String() + stderr.String()

	if strings.Contains(output, "--path") {
		return true, nil
	}

	return false, err
}

func IptablesSupportsOwnerUidMatch() (bool, error) {
	cmd := exec.Command("iptables", "-m", "owner", "--uid-owner")
	cmd.Env = append(os.Environ(), "LANG=C")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String() + stderr.String()

	if strings.Contains(output, "--path") {
		return true, nil
	}

	return false, err
}
