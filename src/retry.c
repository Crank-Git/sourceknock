/* retry.c - throttle for reopening a lost capture interface. */
#include "retry.h"

int capture_retry_due(double last_try, double now)
{
    if (last_try == 0.0)
        return 1;
    return now - last_try >= CAPTURE_RETRY_SECS;
}
