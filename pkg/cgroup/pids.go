package helper

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func GetPidOfCgroup(cGroupPath string) ([]int, error) {
	file, err := os.Open(cGroupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var numbers []int

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		num, err := strconv.Atoi(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse number: %v", err)
		}

		numbers = append(numbers, num)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while reading file: %v", err)
	}

	return numbers, nil
}
