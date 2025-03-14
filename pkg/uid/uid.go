package uid

import "math/rand"

// generate random uid that no process belongs to
func GetRandomUid() int {
	return rand.Intn(1000)
}
