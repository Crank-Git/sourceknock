/*
 * retry.h - throttle for reopening a lost capture interface (pure).
 *
 * No I/O, so the decision is unit-testable on any OS.
 */
#ifndef SOURCEKNOCK_RETRY_H
#define SOURCEKNOCK_RETRY_H

/* Minimum seconds between two reopen attempts on one interface. */
#define CAPTURE_RETRY_SECS 1.0

/* Returns 1 when a reopen attempt is due: `now` is at least
 * CAPTURE_RETRY_SECS after `last_try`. Both are monotonic seconds. A
 * `last_try` of 0 means "never tried", so the first attempt is always due. */
int capture_retry_due(double last_try, double now);

#endif /* SOURCEKNOCK_RETRY_H */
