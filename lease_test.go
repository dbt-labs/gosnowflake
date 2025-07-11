package gosnowflake

import (
	"fmt"
	"github.com/timandy/routine"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLeaseAcquireRenewAndExpire(t *testing.T) {
	leaseFilepath := "acquire_renew_expire.lease"
	ttl := MinRequestedTTL

	handler, err := NewLeaseHandler(leaseFilepath, DefaultLeaseOperationTimeout)
	assertNilF(t, err)
	lease, err := handler.Acquire(ttl)
	assertNilF(t, err)
	// successful Renew()
	err = lease.Renew(ttl)
	assertNilF(t, err)
	time.Sleep(2 * ttl)
	// can't Renew() after expiration
	err = lease.Renew(ttl)
	assertNotNilF(t, err)
}

func TestLeaseAcquireAndRelease(t *testing.T) {
	leaseFilepath := "acquire_release.lease"
	ttl := MinRequestedTTL

	handler, err := NewLeaseHandler(leaseFilepath, DefaultLeaseOperationTimeout)
	assertNilF(t, err)
	lease, err := handler.Acquire(ttl)
	assertNilF(t, err)
	err = lease.Release()
	assertNilF(t, err)
	// can't Renew() after Release()
	err = lease.Renew(ttl)
	assertNotNilF(t, err)
}

// Simulate `n` processes acquiring a lease, sleeping for a random duration
// in [d, m], and releasing the lease.
func SimulateNProcesses(
	t *testing.T, handler *LeaseHandler,
	ttl time.Duration,
	n int, d time.Duration, m time.Duration, explicitRelease bool) {
	var wg sync.WaitGroup
	var holdingLeaseCount int32

	utime := time.Duration(0)
	start := time.Now()
	for range n {
		wg.Add(1)
		if m > d {
			d += time.Duration(rand.Int63n(int64(m - d + 1)))
		}
		utime += d
		go func() {
			defer wg.Done()
			lease, err := handler.Acquire(ttl)
			assertNilF(t, err)

			swapped := atomic.CompareAndSwapInt32(&holdingLeaseCount, 0, 1)
			assertTrueE(t, swapped, "acquired lease should be exclusive")

			for duration := d; duration > 0; {
				step := min(ttl/2, duration)
				fmt.Fprintf(os.Stdout, "[%v] ---- work(%v)\n", routine.Goid(), step)
				time.Sleep(step)
				duration -= step

				if duration > 0 {
					err = lease.Renew(ttl)
					assertNilF(t, err, "failed to renew lease")
				}
			}

			swapped = atomic.CompareAndSwapInt32(&holdingLeaseCount, 1, 0)
			assertTrueE(t, swapped, "more than one lease holder detected")

			if explicitRelease {
				err = lease.Release()
				assertNilF(t, err)
			}
		}()
	}
	wg.Wait()
	wtime := time.Since(start)
	fmt.Fprintf(os.Stdout,
		"Concurrent processes simulation: wall_clock_time=%v, useful_work=%v (%.2f%%)\n",
		wtime,
		utime,
		float64(utime)/float64(wtime)*100.0,
	)
}

func TestSingleProcessLeaseAcquire(t *testing.T) {
	handler, err := NewLeaseHandler("single.lease", DefaultLeaseOperationTimeout)
	assertNilF(t, err)
	SimulateNProcesses(t, handler, MinRequestedTTL, 1, 0, 0, true)
}

func TestConcurrentLeaseAcquire(t *testing.T) {
	handler, err := NewLeaseHandler("concurrent.lease", DefaultLeaseOperationTimeout)
	assertNilF(t, err)
	ttl := MinRequestedTTL // tiny ttl
	SimulateNProcesses(t, handler, ttl, 16, 0, 0, true)
}

func TestConcurrentLeaseAcquireWithRandomDurationProcesses(t *testing.T) {
	handler, err := NewLeaseHandler("concurrent_random.lease", DefaultLeaseOperationTimeout)
	assertNilF(t, err)
	ttl := MinRequestedTTL // tiny ttl
	d := time.Duration(0)
	m := 2 * MinRequestedTTL // max duration of the processes
	SimulateNProcesses(t, handler, ttl, 4, d, m, true)
}

func TestConcurrentLeaseAcquireWithFittingTTL(t *testing.T) {
	timeout := 10 * time.Minute // must be larger than n * d (#processes * duration)
	handler, err := NewLeaseHandler("concurrent_fitting.lease", timeout)
	assertNilF(t, err)
	ttl := 4 * time.Second // well-sized TTL
	d := 4 * time.Second   // TTL equals the duration of the processes
	SimulateNProcesses(t, handler, ttl, 4, d, d, true)
}
