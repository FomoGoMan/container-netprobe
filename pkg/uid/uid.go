package uid

import (
	"fmt"
	"math/rand"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// GenerateUnusedUID generates a random unused UID (no process using it)
func GenerateUnusedUID() (int, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	maxRetries := 1000

	for i := 0; i < maxRetries; i++ {
		uid := r.Intn(60000) + 1000
		pids, err := GetPIDsByUID(uid)
		if err != nil {
			return 0, fmt.Errorf("failed to check UID %d: %v", uid, err)
		}
		if len(pids) == 0 {
			return uid, nil
		}
	}

	return 0, fmt.Errorf("failed to find an unused UID after %d retries", maxRetries)
}

func GetPIDsByUID(uid int) ([]int, error) {
	cmd := exec.Command("ps", "-o", "pid=", "-u", strconv.Itoa(uid))
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute ps command: %v", err)
	}

	pids := []int{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PID: %v", err)
		}
		pids = append(pids, pid)
	}

	return pids, nil
}

// func main() {
//
// 	uid, err := GenerateUnusedUID()
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}
// 	fmt.Printf("Generated unused UID: %d\n", uid)

//
// 	pids, err := GetPIDsByUID(1000)
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}
// 	fmt.Printf("PIDs for UID 1000: %v\n", pids)
// }
