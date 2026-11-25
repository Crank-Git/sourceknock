/* retry_test.c - unit tests for the capture reopen throttle. */
#include "retry.h"
#include "test.h"

static void test_first_attempt_is_due(void)
{
    CHECK(capture_retry_due(0.0, 0.1));
    CHECK(capture_retry_due(0.0, 1000.0));
}

static void test_not_due_before_one_second(void)
{
    CHECK(!capture_retry_due(100.0, 100.0));
    CHECK(!capture_retry_due(100.0, 100.5));
    CHECK(!capture_retry_due(100.0, 100.999));
}

static void test_due_after_one_second(void)
{
    CHECK(capture_retry_due(100.0, 101.0));
    CHECK(capture_retry_due(100.0, 130.0));
}

int main(void)
{
    printf("== capture retry throttle tests ==\n");
    TEST_RUN(test_first_attempt_is_due);
    TEST_RUN(test_not_due_before_one_second);
    TEST_RUN(test_due_after_one_second);
    TEST_SUMMARY();
}
