package general

type SuspiciousDetector interface {
	EnableSuspiciousDetect() (detected chan int, err error)
}
