#if defined(__TARGET_ARCH_arm64)
#include "vmlinux-arm64.h"
#elif defined(__TARGET_ARCH_arm)
#include "vmlinux-arm.h"
#else
#include "vmlinux-x86.h"
#endif