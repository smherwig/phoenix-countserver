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
#include <rpc.h>

#include <bearssl/bearssl.h>

#include <tcad.h>

#define NUM_TRIALS 10

#define COUNTER_SIZE 4
#define KEY_SIZE 16
#define IV_SIZE 12
#define TAG_SIZE 16

#define AD_SIZE (COUNTER_SIZE + KEY_SIZE + IV_SIZE + TAG_SIZE)

#define AD_COUNTER_POS  0
#define AD_KEY_POS      COUNTER_SIZE
#define AD_IV_POS       AD_KEY_POS + KEY_SIZE
#define AD_TAG_POS      AD_IV_POS + IV_SIZE

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

struct tl {
    int ticket_number;      /* untrusted */
    int turn;               /* untrusted/trusted/server */
};

struct segment {
    /* use the convention of having a path for the name,
     * even though the pathname structure carries no meaning
     */
    char    *name;          
    size_t  size;
    void    *pub_mem;       /* untrusted */
    void    *priv_mem;      /* trusted */
    uint8_t iv[IV_SIZE];    /* trusted/server */
    uint8_t key[32];        /* trusted/server */
    uint8_t tag[16];        /* trusted/server */
    struct tl *tl;          /* untrusted */
    int     turn;
    int     tcad_fd;
};

struct tcad_client {
    struct rpc_agent   *cli_agent;
};

struct secmem {
    struct tcad_client *client; 
    struct segment *segment;
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

static void
encrypt(uint8_t *data, size_t data_len, const uint8_t *key, const uint8_t *iv,
        uint8_t *tag)
{
    br_aes_x86ni_ctr_keys ctx;
    br_gcm_context gc;

    RHO_TRACE_ENTER();

    br_aes_x86ni_ctr_init(&ctx, key, RHO_C_ARRAY_SIZE(default_key));
    br_gcm_init(&gc, &ctx.vtable, br_ghash_pclmul);
    br_gcm_reset(&gc, iv, IV_SIZE); 
    /* use br_gc_aad_inject, if needed */
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 1, data, data_len); /* encrypts in-place */
    br_gcm_get_tag(&gc, tag);

    RHO_TRACE_EXIT();
}

static void
decrypt(uint8_t *data, size_t data_len, const uint8_t *key, const uint8_t *iv,
        uint8_t *tag)
{
    br_aes_x86ni_ctr_keys ctx;
    br_gcm_context gc;

    RHO_TRACE_ENTER();

    br_aes_x86ni_ctr_init(&ctx, key, RHO_C_ARRAY_SIZE(default_key));
    br_gcm_init(&gc, &ctx.vtable, br_ghash_pclmul);
    br_gcm_reset(&gc, iv, IV_SIZE); 
    /* use br_gc_aad_inject, if needed */
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 0, data, data_len); /* encrypts in-place */
    br_gcm_get_tag(&gc, tag);

    RHO_TRACE_EXIT();
}

/******************************************
 * TCAD Client
 ******************************************/
static int
tcad_new_fdtable(struct tcad_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rpc_hdr *hdr = &agent->ra_hdr;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, TCAD_OP_NEW_FDTABLE);

    /* make request */
    error = rpc_agent_request(agent);
    if (error != 0) {
        /* RPC/transport error */
        goto done;
    }

    if (hdr->rh_code != 0) {
        /* method error */
        goto done;
    }

done:
    RHO_TRACE_EXIT();
    return (error);
}

static struct tcad_client *
tcad_connect(const char *url)
{
    struct tcad_client *client = NULL;
    struct rho_sock *sock = NULL;

    RHO_TRACE_ENTER("url=\"%s\"", url);

    sock = rho_sock_from_url(url);
    rho_sock_connect_url(sock, url);

    client = rhoL_zalloc(sizeof(*client));
    client->cli_agent = rpc_agent_create(sock, NULL);

    tcad_new_fdtable(client);

    RHO_TRACE_EXIT();
    return (client);
}

/* returns 0 on success, or an errno value on failure */
static int
tcad_create_entry(struct tcad_client *client, const char *name, void *data,
        size_t data_len, int *fd)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct rpc_hdr *hdr = &agent->ra_hdr;

    RHO_TRACE_ENTER();

    /* build request */
    rpc_agent_new_msg(agent, TCAD_OP_CREATE_ENTRY);
    rho_buf_write_u32size_str(buf, name);
    rho_buf_write_u32size_blob(buf, data, data_len);
    rpc_agent_autoset_bodylen(agent);

    /* make request */
    error = rpc_agent_request(agent);
    if (error != 0) {
        /* RPC/transport error (EPROTO) */
        rho_warn("RPC error");
        goto done;
    }

    if (hdr->rh_code != 0) {
        /* method error */
        error = hdr->rh_code;
        rho_errno_warn(error, "RPC returned an error");
        goto done;
    }

    rho_buf_readu32be(buf, (uint32_t *)&fd);

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
tcad_destroy_entry(struct tcad_client *client, int fd)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct rpc_hdr *hdr = &agent->ra_hdr;

    RHO_TRACE_ENTER();

    /* build request */
    rpc_agent_new_msg(agent, TCAD_OP_DESTROY_ENTRY);
    rho_buf_writeu32be(buf, fd);
    rpc_agent_autoset_bodylen(agent);

    /* make request */
    error = rpc_agent_request(agent);
    if (error != 0) {
        /* RPC/transport error */
        rho_warn("RPC error");
        goto done;
    }

    if (hdr->rh_code != 0) {
        /* method error */
        error = hdr->rh_code;
        rho_errno_warn(error, "RPC returned an error");
        goto done;
    }

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
tcad_cmp_and_get(struct tcad_client *client, int fd, int expected_count,
        void *data, size_t *data_len)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct rpc_hdr *hdr = &agent->ra_hdr;

    RHO_TRACE_ENTER();

    /* build request */
    rpc_agent_new_msg(agent, TCAD_OP_CMP_AND_GET);
    rho_buf_writeu32be(buf, fd);
    rho_buf_write32be(buf, expected_count); 
    rpc_agent_autoset_bodylen(agent);

    /* make request */
    error = rpc_agent_request(agent);
    if (error != 0) {
        /* RPC/transport error */
        rho_warn("RPC error");
        goto done;
    }

    if (hdr->rh_code != 0) {
        /* method error */
        error = hdr->rh_code;
        rho_errno_warn(error, "RPC returned an error");
        goto done;
    }

    rho_buf_read_u32size_blob(buf, data, 256, data_len);

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
tcad_inc_and_set(struct tcad_client *client, int fd, void *data,
        size_t data_len)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct rpc_hdr *hdr = &agent->ra_hdr;

    RHO_TRACE_ENTER();

    /* build request */
    rpc_agent_new_msg(agent, TCAD_OP_INC_AND_SET);
    rho_buf_writeu32be(buf, fd);
    rho_buf_write_u32size_blob(buf, data, data_len);
    rpc_agent_autoset_bodylen(agent);

    /* make request */
    error = rpc_agent_request(agent);
    if (error != 0) {
        /* RPC/transport error */
        rho_warn("RPC error");
        goto done;
    }

    if (hdr->rh_code != 0) {
        /* method error */
        error = hdr->rh_code;
        rho_errno_warn(error, "RPC returned an error");
        goto done;
    }

    /* no body */

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
tcad_disconnect(struct tcad_client *client)
{
    RHO_TRACE_ENTER();
    (void)client;
    RHO_TRACE_EXIT();
    return (0);
}

/******************************************
 * Ticket-Lock
 ******************************************/

static struct tl *
tl_create(void)
{
    struct tl *tl = NULL;

    RHO_TRACE_ENTER();

    /* this memory will be untrusted */
    tl = mmap(NULL, sizeof(struct tl), PROT_READ|PROT_WRITE,
        MAP_ANONYMOUS|MAP_SHARED, -1, 0);    
    if (tl == NULL)
        rho_errno_die(errno, "mmap");

    tl->ticket_number = 0;
    tl->turn = 0;

    RHO_TRACE_EXIT();
    return (tl);
}

static void
tl_destroy(struct tl *tl)
{
    int error = 0;    

    RHO_TRACE_ENTER();
    
    error = munmap(tl, sizeof(*tl));
    if (error == -1)
        rho_errno_warn(errno, "munmap");

    RHO_TRACE_EXIT();
}

static int
tl_lock(struct tl *tl)
{
    int my_turn;

    my_turn = rho_atomic_fetch_inc(&tl->ticket_number);
    while (my_turn != tl->turn) { /* spin */ ; }
    return (my_turn);
}

static void
tl_unlock(struct tl *tl)
{
    rho_atomic_fetch_inc(&tl->turn);
}

/******************************************
 * SEGMENT
 ******************************************/

static struct segment *
segment_create(const char *name, size_t size)
{
    struct segment *seg = NULL;

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

    seg->tl = tl_create();

    rho_rand_bytes(seg->iv, IV_SIZE);
    memcpy(seg->key, default_key, 32);

    encrypt(seg->priv_mem, seg->size, seg->key, seg->iv, seg->tag);
    memcpy(seg->pub_mem, seg->priv_mem, seg->size);

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

    tl_destroy(seg->tl);

    rhoL_free(seg);

    RHO_TRACE_EXIT();
}

/* decrypt file into private memory */
static int
segment_map_in(struct segment *seg)
{
    int error = 0;
    uint8_t actual_tag[TAG_SIZE] = {0};

    RHO_TRACE_ENTER();

    memcpy(seg->priv_mem, seg->pub_mem, seg->size);
    decrypt(seg->priv_mem, seg->size, seg->key, seg->iv, actual_tag);

    if (!rho_mem_equal(seg->tag, actual_tag, TAG_SIZE)) {
        rho_warn("on segment \"%s\"map in, tag does not match trusted tag",
                seg->name);
        error = EBADE;  /* invalid exchange */
    }

    RHO_TRACE_EXIT();
    return (error);
}

/* encrypt private memory to file */
static void
segment_map_out(struct segment *seg)
{
    RHO_TRACE_ENTER();

    rho_rand_bytes(seg->iv, IV_SIZE);
    encrypt(seg->priv_mem, seg->size, seg->key, seg->iv, seg->tag);
    memcpy(seg->pub_mem, seg->priv_mem, seg->size);

    RHO_TRACE_EXIT();
}

/******************************************
 * SERIALIZE/DESERIALIZE HELPERS
 ******************************************/
static void
pack_segment_ad(const struct segment *seg, void *ad)
{
    int32_t turn_be = htobe32(seg->turn);

    RHO_TRACE_ENTER();

    memcpy(ad,              &turn_be, sizeof(turn_be));
    memcpy(ad + AD_KEY_POS, seg->key, KEY_SIZE);
    memcpy(ad + AD_IV_POS,  seg->iv,  IV_SIZE);
    memcpy(ad + AD_TAG_POS, seg->tag, TAG_SIZE);

    RHO_TRACE_EXIT();
}

static void
unpack_segment_ad(const void *ad, struct segment *seg)
{
    RHO_TRACE_ENTER();

    memcpy(seg->iv,  ad + AD_IV_POS,  IV_SIZE);
    memcpy(seg->tag, ad + AD_TAG_POS, TAG_SIZE);

    RHO_TRACE_EXIT();
}

/******************************************
 * SECMEM
 ******************************************/
static struct secmem *
secmem_create(const char *url)
{
    struct secmem *sm = NULL;

    RHO_TRACE_ENTER();

    sm = rhoL_zalloc(sizeof(*sm));
    sm->client = tcad_connect(url);

    RHO_TRACE_EXIT();

    return (sm);
}

static void
secmem_destroy(struct secmem *sm)
{
    RHO_TRACE_ENTER();
    
    tcad_disconnect(sm->client); 
    rhoL_free(sm);

    RHO_TRACE_EXIT();
}

static int
secmem_create_segment(struct secmem *sm, const char *name, size_t size)
{
    int error = 0;
    uint8_t ad[AD_SIZE] = {0};

    RHO_TRACE_ENTER();

    sm->segment = segment_create(name, size);
    pack_segment_ad(sm->segment, ad);
    error = tcad_create_entry(sm->client, sm->segment->name, ad, AD_SIZE,
            &sm->segment->tcad_fd);

    RHO_TRACE_EXIT();
    return (error);
}

static void
secmem_destroy_segment(struct secmem *sm)
{
    struct segment *seg = sm->segment;

    RHO_TRACE_ENTER();

    tcad_destroy_entry(sm->client, seg->tcad_fd);
    segment_destroy(seg);
    sm->segment = NULL;

    RHO_TRACE_EXIT();
}

static int
secmem_lock(struct secmem *sm)
{
    int error = 0;
    uint8_t ad[AD_SIZE] = {0};
    size_t ad_size = 0;
    struct segment *seg = sm->segment;
    TIMER_DECL(timer);

    RHO_TRACE_ENTER();

    seg->turn = tl_lock(seg->tl);

timer_start(&timer);

    error = tcad_cmp_and_get(sm->client, seg->tcad_fd, seg->turn, ad,
            &ad_size);
    if (error != 0)
        goto done;

    unpack_segment_ad(ad, seg);
    error = segment_map_in(seg);

timer_stop(&timer);
    lock_times[trial] = timer_get_elapsed(&timer);
    fprintf(stderr, "time for map in: %f secs\n", timer_get_elapsed(&timer));

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
secmem_unlock(struct secmem *sm)
{ 
    int error = 0;
    uint8_t ad[AD_SIZE] = {0};
    struct segment *seg = sm->segment;
    TIMER_DECL(timer);

    RHO_TRACE_ENTER();

timer_start(&timer);

    segment_map_out(seg);
    pack_segment_ad(seg, ad);

    error = tcad_inc_and_set(sm->client, seg->tcad_fd, ad, sizeof(ad));

timer_stop(&timer);
    unlock_times[trial] = timer_get_elapsed(&timer);
    fprintf(stderr, "time for map out: %f secs\n", timer_get_elapsed(&timer));

    tl_unlock(seg->tl);

    RHO_TRACE_EXIT();
    return (error);
}

static void
usage(int exit_code)
{
    fprintf(stderr, "tcadclient SERVER_URL SEGMENT_NAME SEGMENT_SIZE\n");
    exit(exit_code);
}

/******************************************
 * Example Program
 *
 * argv[1] = server url
 * argv[2] = name of segment to create
 * argv[3] = segment size (in bytes)
 ******************************************/
int
main(int argc, char *argv[])
{
    int error = 0;
    struct secmem *sm = NULL;
    uint32_t seg_size = 0;

    if (argc != 4)
        usage(1);

    seg_size = rho_str_touint32(argv[3], 10);
    sm = secmem_create(argv[1]);
    error = secmem_create_segment(sm, argv[2], seg_size);
    if (error != 0)
        rho_errno_die(error, "secmem_create_segment");

    for (trial = 0; trial < NUM_TRIALS; trial++) {
        error = secmem_lock(sm);
        if (error != 0)
            rho_errno_die(error, "secmem_lock");

        rho_hexdump(sm->segment->priv_mem, 16, "priv_mem on lock (trial=%d)",
                trial);
        memcpy(sm->segment->priv_mem + 8, "AAAAAAAA", 8);
        
        error = secmem_unlock(sm);
        if (error != 0)
            rho_errno_die(error, "secmem_unlock");
        //rho_hexdump(sm->priv_mem, 16, "parent priv_mem on unlock (i=%d)", i);
        random_sleep();
    }

    secmem_destroy_segment(sm);
    secmem_destroy(sm);

    printf("trimmed mean:\n");
    printf("    lock: %f\n", trimmed_mean(lock_times, NUM_TRIALS));
    printf("  unlock: %f\n", trimmed_mean(unlock_times, NUM_TRIALS));

    return (0);
}
