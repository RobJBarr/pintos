#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <list.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "devices/pit.h"
#include "lib/fixedpoint.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

#define PRIORITY_UPDATE 4

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

/* Sorted queue of asleep threads */
static struct list asleep_list;

static intr_handler_func timer_interrupt;
static bool too_many_loops(unsigned loops);
static void busy_wait(int64_t loops);
static void real_time_sleep(int64_t num, int32_t denom);
static void real_time_delay(int64_t num, int32_t denom);

/* Sets up the timer to interrupt TIMER_FREQ times per second,
   and registers the corresponding interrupt. */
void timer_init(void) {
  list_init(&asleep_list);
  pit_configure_channel(0, 2, TIMER_FREQ);
  intr_register_ext(0x20, timer_interrupt, "8254 Timer");
  load_avg = 0;
}

/* Calibrates loops_per_tick, used to implement brief delays. */
void timer_calibrate(void) {
  unsigned high_bit, test_bit;

  ASSERT(intr_get_level() == INTR_ON);
  printf("Calibrating timer...  ");

  /* Approximate loops_per_tick as the largest power-of-two
     still less than one timer tick. */
  loops_per_tick = 1u << 10;
  while (!too_many_loops(loops_per_tick << 1)) {
    loops_per_tick <<= 1;
    ASSERT(loops_per_tick != 0);
  }

  /* Refine the next 8 bits of loops_per_tick. */
  high_bit = loops_per_tick;
  for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
    if (!too_many_loops(high_bit | test_bit)) loops_per_tick |= test_bit;

  printf("%'" PRIu64 " loops/s.\n", (uint64_t)loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
int64_t timer_ticks(void) {
  enum intr_level old_level = intr_disable();
  int64_t t = ticks;
  intr_set_level(old_level);
  return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t timer_elapsed(int64_t then) { return timer_ticks() - then; }

/* Compare function for 2 list_elems that are contained by
   struct asleep_elem elements. Returns True if a < b, that
   is if the wake up time of a is before the wake up time
   of b. */
static bool compare_asleep_time(const struct list_elem *a,
                                const struct list_elem *b, void *aux UNUSED) {
  return list_entry(a, struct asleep_elem, elem)->wakeup_time <
         list_entry(b, struct asleep_elem, elem)->wakeup_time;
}

/* Sleeps for approximately TICKS timer ticks.  Interrupts must
   be turned on. */
void timer_sleep(int64_t ticks) {
  int64_t start = timer_ticks();

  ASSERT(intr_get_level() == INTR_ON);

  /* Initialise a new element for the asleep queue. */
  struct asleep_elem asleep_log;
  sema_init(&(asleep_log.wakeup_signal), 0);
  asleep_log.wakeup_time = start + ticks;

  /* Add it to the list and wait for the semaphore to go up
     in the interrupt handler. */
  enum intr_level old_level = intr_disable();
  list_insert_ordered(&asleep_list, &(asleep_log.elem), &compare_asleep_time,
                      NULL);
  sema_down(&(asleep_log.wakeup_signal));
  intr_set_level(old_level);
}

/* Sleeps for approximately MS milliseconds.  Interrupts must be
   turned on. */
void timer_msleep(int64_t ms) { real_time_sleep(ms, 1000); }

/* Sleeps for approximately US microseconds.  Interrupts must be
   turned on. */
void timer_usleep(int64_t us) { real_time_sleep(us, 1000 * 1000); }

/* Sleeps for approximately NS nanoseconds.  Interrupts must be
   turned on. */
void timer_nsleep(int64_t ns) { real_time_sleep(ns, 1000 * 1000 * 1000); }

/* Busy-waits for approximately MS milliseconds.  Interrupts need
   not be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_msleep()
   instead if interrupts are enabled. */
void timer_mdelay(int64_t ms) { real_time_delay(ms, 1000); }

/* Sleeps for approximately US microseconds.  Interrupts need not
   be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_usleep()
   instead if interrupts are enabled. */
void timer_udelay(int64_t us) { real_time_delay(us, 1000 * 1000); }

/* Sleeps execution for approximately NS nanoseconds.  Interrupts
   need not be turned on.

   Busy waiting wastes CPU cycles, and busy waiting with
   interrupts off for the interval between timer ticks or longer
   will cause timer ticks to be lost.  Thus, use timer_nsleep()
   instead if interrupts are enabled.*/
void timer_ndelay(int64_t ns) { real_time_delay(ns, 1000 * 1000 * 1000); }

/* Prints timer statistics. */
void timer_print_stats(void) {
  printf("Timer: %" PRId64 " ticks\n", timer_ticks());
}

/* Calculate new load_avg */
void update_load_avg(void) {
  enum intr_level old_level = intr_disable();
  int ready_threads = threads_ready();
  // Take into account the currently running thread too
  strcmp(thread_current()->name, "idle") == 0 ? 0 : ready_threads++;
  load_avg = add(59 * load_avg, ready_threads) / 60;
  intr_set_level(old_level);
}

/* Timer interrupt handler. */
static void timer_interrupt(struct intr_frame *args UNUSED) {
  ticks++;
  thread_tick();

  /* Every interrupt, the running thread's recent_cpu is incremented. */
  if (strcmp(thread_current()->name, "idle") != 0) {
    // We only want to do this to a running thread
    // thread_current()->recent_cpu++;
    thread_current()->recent_cpu = add(thread_current()->recent_cpu, 1);
  }
  /* Check the tick counter, update recent_cpu every second and
   * priority levels every 4th tick */
  if (thread_mlfqs) {
    if (timer_ticks() % TIMER_FREQ == 0) {
      update_load_avg();
      thread_foreach(update_recent_cpu, NULL);
    }
    if (timer_ticks() % PRIORITY_UPDATE == 0) {
      thread_foreach(update_priority, NULL);
    }
  }

  /* Wake up all the threads whose timer expired. Checks
     only the top element because the queue is sorted. */
  while (!list_empty(&asleep_list)) {
    struct list_elem *asleep_elem = list_begin(&asleep_list);
    struct asleep_elem *asleep_entry =
        list_entry(asleep_elem, struct asleep_elem, elem);
    if (timer_elapsed(asleep_entry->wakeup_time) < 0) {
      break;
    }

    sema_up(&(asleep_entry->wakeup_signal));
    list_pop_front(&asleep_list);
  }
}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool too_many_loops(unsigned loops) {
  /* Wait for a timer tick. */
  int64_t start = ticks;
  while (ticks == start) barrier();

  /* Run LOOPS loops. */
  start = ticks;
  busy_wait(loops);

  /* If the tick count changed, we iterated too long. */
  barrier();
  return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE busy_wait(int64_t loops) {
  while (loops-- > 0) barrier();
}

/* Sleep for approximately NUM/DENOM seconds. */
static void real_time_sleep(int64_t num, int32_t denom) {
  /* Convert NUM/DENOM seconds into timer ticks, rounding down.

        (NUM / DENOM) s
     ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
     1 s / TIMER_FREQ ticks
  */
  int64_t ticks = num * TIMER_FREQ / denom;

  ASSERT(intr_get_level() == INTR_ON);
  if (ticks > 0) {
    /* We're waiting for at least one full timer tick.  Use
       timer_sleep() because it will yield the CPU to other
       processes. */
    timer_sleep(ticks);
  } else {
    /* Otherwise, use a busy-wait loop for more accurate
       sub-tick timing. */
    real_time_delay(num, denom);
  }
}

/* Busy-wait for approximately NUM/DENOM seconds. */
static void real_time_delay(int64_t num, int32_t denom) {
  /* Scale the numerator and denominator down by 1000 to avoid
     the possibility of overflow. */
  ASSERT(denom % 1000 == 0);
  busy_wait(loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
}
