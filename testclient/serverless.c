#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define _BSD_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <rho/rho.h>

#include <bearssl/bearssl.h>

#define NUM_TRIALS 10

#define KEY_SIZE 16
#define IV_SIZE 12

static uint8_t default_key[] = {
    0x41, 0x42, 0x43, 0x44,
    0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x4b, 0x4c,
    0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54,
    0x55, 0x56, 0x57, 0x58,
    0x59, 0x5a, 0x5b, 0x5c,
    0x5d, 0x5e, 0x5f, 0x60,
};

/* for benchmarking */
int trial = 0;
double lock_times[NUM_TRIALS] = { 0 };
double unlock_times[NUM_TRIALS] = { 0 };

struct timer {
    clock_t start;
    clock_t stop;
};

#define TIMER_DECL(name) \
    struct timer name = { 0, 0 }

struct tlad {
    int ticket_number;      /* untrusted */
    int turn;               /* untrusted/trusted/server */
    size_t data_size;
    uint8_t data[];
};

struct segment {
    /* use the convention of having a path for the name,
     * even though the pathname structure carries no meaning
     */
    char    *name;          
    size_t  size;
    void    *pub_mem;       /* untrusted */
    void    *priv_mem;      /* trusted */
    uint8_t key[32];        /* trusted */
    struct tlad *tlad;      /* untrusted */
    int     turn;
};

/******************************************
 * TIMER
 ******************************************/
static inline void
timer_start(struct timer *timer)
{
    timer->start = clock();
}

static inline void
timer_stop(struct timer *timer)
{
    timer->stop = clock();
}

/* returns seconds */
static inline double
timer_get_elapsed(struct timer *timer)
{
    return ((double)(timer->stop - timer->start) / CLOCKS_PER_SEC);
}

/******************************************
 * BENCHMARK HELPERS
 ******************************************/
/* 
 * computes the 30% trimmed mean (bottom 30% and top 30% of
 * results are removed, and the mean is calculated from the middle
 * 40%)
 */

static int
double_cmp(const void *a, const void *b)
{
    double da = *((double *)a);
    double db = *((double *)b);

    if (da > db)
        return (1);
    else if (da == db)
        return (0);
    else
        return (-1);
}

static double
trimmed_mean(double *trials, size_t trial_size)
{
    int i = 0;
    int lo = 0;
    int hi = 0;
    double sum = 0;

    qsort(trials, trial_size, sizeof(double), double_cmp);

    lo = (int)(0.3 * trial_size);
    hi = (int)(0.7 * trial_size);

    for (i = lo; i < hi; i++)
        sum += trials[i];

    sum /= 4.0;
    return (sum);
}

/******************************************
 * MISC
 ******************************************/
static void
random_sleep(void)
{
    int r = 0;

    r = rand() / 10000;
    usleep(r);
}

/******************************************
 * CIPHER
 ******************************************/

/* encrypt priv_mem to fd */
static void
encrypt(uint8_t *data, size_t data_len, const uint8_t *key, const uint8_t *iv)
{
    br_aes_x86ni_ctr_keys ctx;
    uint32_t cc = 0;
    uint32_t cc_out = 0;

    RHO_TRACE_ENTER();

    br_aes_x86ni_ctr_init(&ctx, key, RHO_C_ARRAY_SIZE(default_key));
    cc_out = br_aes_x86ni_ctr_run(&ctx, iv, cc, data, data_len);
    fprintf(stderr, "encrypted (data_len=%zu, cc_out=%" PRIu32 ")\n",
            data_len, cc_out);

    RHO_TRACE_EXIT();
}

/* decrypt fd to priv_mem */
static void
decrypt(uint8_t *data, size_t data_len, const uint8_t *key, const uint8_t *iv)
{
    br_aes_x86ni_ctr_keys ctx;
    uint32_t cc = 0;
    uint32_t cc_out = 0;

    RHO_TRACE_ENTER();

    br_aes_x86ni_ctr_init(&ctx, key, RHO_C_ARRAY_SIZE(default_key));
    cc_out = br_aes_x86ni_ctr_run(&ctx, iv, cc, data, data_len);
    fprintf(stderr, "decrypted (data_len=%zu, cc_out=%"PRIu32")\n",
            data_len, cc_out);

    RHO_TRACE_EXIT();
}

/******************************************
 * Ticket-Lock (with associated data (i.e, the IV)
 ******************************************/

static struct tlad *
tlad_create(size_t data_size)
{
    struct tlad *tlad = NULL;

    RHO_TRACE_ENTER();

    /* this memory will be untrusted */
    tlad = mmap(NULL, sizeof(struct tlad) + data_size, PROT_READ|PROT_WRITE,
        MAP_ANONYMOUS|MAP_SHARED, -1, 0);    
    if (tlad == NULL)
        rho_errno_die(errno, "mmap");

    tlad->ticket_number = 0;
    tlad->turn = 0;
    tlad->data_size = data_size;

    RHO_TRACE_EXIT();
    return (tlad);
}

static void
tlad_destroy(struct tlad *tlad)
{
    int error = 0;    

    RHO_TRACE_ENTER();
    
    error = munmap(tlad, sizeof(struct tlad) + tlad->data_size);
    if (error == -1)
        rho_errno_warn(errno, "munmap");

    RHO_TRACE_EXIT();
}

static int
tlad_lock(struct tlad *tlad)
{
    int my_turn;

    my_turn = rho_atomic_fetch_inc(&tlad->ticket_number);
    while (my_turn != tlad->turn) { /* spin */ ; }
    return (my_turn);
}

static void
tlad_unlock(struct tlad *tlad)
{
    rho_atomic_fetch_inc(&tlad->turn);
}

/******************************************
 * SEGMENT
 ******************************************/

static struct segment *
segment_create(const char *name, size_t size)
{
    struct segment *seg = NULL;
    uint8_t iv[IV_SIZE] = {0};

    RHO_TRACE_ENTER();

    seg = rhoL_zalloc(sizeof(*seg));

    seg->name = rhoL_strdup(name);
    seg->size = size;

    seg->pub_mem =  mmap(NULL, size, PROT_READ|PROT_WRITE, 
            MAP_ANONYMOUS|MAP_SHARED, -1, 0);    
    if (seg->pub_mem == NULL)
        rho_errno_die(errno, "mmap");

    seg->priv_mem = mmap(NULL, size, PROT_READ|PROT_WRITE,
            MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    seg->tlad = tlad_create(IV_SIZE);

    rho_rand_bytes(iv, IV_SIZE);
    memcpy(seg->key, default_key, 32);

    encrypt(seg->priv_mem, seg->size, seg->key, iv);
    memcpy(seg->pub_mem, seg->priv_mem, seg->size);
    memcpy(seg->tlad->data, iv, sizeof(iv));

    RHO_TRACE_EXIT();
    return (seg);
}

static void
segment_destroy(struct segment *seg)
{
    int error = 0;

    RHO_TRACE_ENTER();

    rhoL_free(seg->name);

    error = munmap(seg->pub_mem, seg->size);
    if (error == -1)
        rho_errno_warn(errno, "munmap");

    error = munmap(seg->priv_mem, seg->size);
    if (error == -1)
        rho_errno_warn(errno, "munmap");

    tlad_destroy(seg->tlad);

    rhoL_free(seg);

    RHO_TRACE_EXIT();
}

/* decrypt file into private memory */
static void
segment_map_in(struct segment *seg)
{
    RHO_TRACE_ENTER();

    memcpy(seg->priv_mem, seg->pub_mem, seg->size);
    decrypt(seg->priv_mem, seg->size, seg->key, seg->tlad->data);

    RHO_TRACE_EXIT();
}

/* encrypt private memory to file */
static void
segment_map_out(struct segment *seg)
{
    uint8_t iv[IV_SIZE] = {0};

    RHO_TRACE_ENTER();

    rho_rand_bytes(iv, IV_SIZE);
    encrypt(seg->priv_mem, seg->size, seg->key, iv);
    memcpy(seg->pub_mem, seg->priv_mem, seg->size);
    memcpy(seg->tlad->data, iv, sizeof(iv));

    RHO_TRACE_EXIT();
}

static void
segment_lock(struct segment *seg)
{
    TIMER_DECL(timer);

    RHO_TRACE_ENTER();

    seg->turn = tlad_lock(seg->tlad);

timer_start(&timer);
    segment_map_in(seg);
timer_stop(&timer);
    lock_times[trial] = timer_get_elapsed(&timer);
    fprintf(stderr, "time for map in: %f secs\n", timer_get_elapsed(&timer));

    RHO_TRACE_EXIT();
}

static void
segment_unlock(struct segment *seg)
{ 
    TIMER_DECL(timer);

    RHO_TRACE_ENTER();

timer_start(&timer);
    segment_map_out(seg);
timer_stop(&timer);
    unlock_times[trial] = timer_get_elapsed(&timer);
    fprintf(stderr, "time for map out: %f secs\n", timer_get_elapsed(&timer));

    tlad_unlock(seg->tlad);

    RHO_TRACE_EXIT();
}

static void
usage(int exit_code)
{
    fprintf(stderr, "serverless SEGMENT_NAME SEGMENT_SIZE\n");
    exit(exit_code);
}

/******************************************
 * Example Program
 *
 * argv[1] = name of segment to create
 * argv[2] = size of segment (in bytes)
 ******************************************/
int
main(int argc, char *argv[])
{
    struct segment *seg = NULL;
    uint32_t seg_size = 0;

    if (argc != 3)
        usage(1);

    seg_size = rho_str_touint32(argv[2], 10);
    seg = segment_create(argv[1], seg_size);

    for (trial = 0; trial < NUM_TRIALS; trial++) {
        segment_lock(seg);
        rho_hexdump(seg->priv_mem, 16, "priv_mem on lock (trial=%d)", trial);
        memcpy(seg->priv_mem + 8, "AAAAAAAA", 8);
        segment_unlock(seg);
        //rho_hexdump(sm->priv_mem, 16, "parent priv_mem on unlock (i=%d)", i);
        random_sleep();
    }

    segment_destroy(seg);

    printf("trimmed mean:\n");
    printf("    lock: %f\n", trimmed_mean(lock_times, NUM_TRIALS));
    printf("  unlock: %f\n", trimmed_mean(unlock_times, NUM_TRIALS));

    return (0);
}
