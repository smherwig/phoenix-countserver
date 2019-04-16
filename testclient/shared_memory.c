#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

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

#define ITERATIONS 10
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

struct timer {
    clock_t start;
    clock_t stop;
};

#define TIMER_DECL(name) \
    struct timer name = { 0, 0 }

struct tl {
    int ticket_number;
    int turn;
};

struct segment {
    char    *path;
    size_t  size;
    void    *file_mem;
    void    *priv_mem;
    uint8_t iv[IV_SIZE];
    uint8_t key[32];
    uint8_t tag[16];
};


struct tcad_client {
    struct rpc_agent   *cli_agent;
};


struct secmem {
    struct tcad_client *client; 
    struct segment *segment;
    struct tl *tl;
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
 * CIPHER
 ******************************************/

/* encrypt priv_mem to fd */
static void
encrypt(uint8_t *data, size_t data_len, const uint8_t *key, const uint8_t *iv,
        uint8_t *tag)
{
    br_aes_x86ni_ctr_keys ctx;
    br_gcm_context gc;

    br_aes_x86ni_ctr_init(&ctx, key, RHO_C_ARRAY_SIZE(default_key));
    br_gcm_init(&gc, &ctx.vtable, br_ghash_pclmul);
    br_gcm_reset(&gc, iv, IV_SIZE); 
    /* use br_gc_aad_inject, if needed */
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 1, data, data_len); /* encrypts in-place */
    br_gcm_get_tag(&gc, tag);
}

/* decrypt fd to priv_mem */
static void
decrypt(uint8_t *data, size_t data_len, const uint8_t *key, const uint8_t *iv,
        uint8_t *tag)
{
    br_aes_x86ni_ctr_keys ctx;
    br_gcm_context gc;

    br_aes_x86ni_ctr_init(&ctx, key, RHO_C_ARRAY_SIZE(default_key));
    br_gcm_init(&gc, &ctx.vtable, br_ghash_pclmul);
    br_gcm_reset(&gc, iv, IV_SIZE); 
    /* use br_gc_aad_inject, if needed */
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 0, data, data_len); /* encrypts in-place */
    br_gcm_get_tag(&gc, tag);
}

/******************************************
 * TCAD Client
 ******************************************/

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

    RHO_TRACE_EXIT();
    return (client);
}

static int
tcad_create_entry(struct tcad_client *client, const char *name, void *data,
        size_t data_len)
{
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct rpc_hdr *hdr = &agent->ra_hdr;

    RHO_TRACE_ENTER();

    /* build request */
    rpc_agent_new_msg(agent, TCAD_OP_CREATE_ENTRY);
    rho_buf_write_u32size_str(buf, purl->path);
    rho_buf_write_u32size_blob(buf, data, data_len);
    rpc_agent_autoset_bodylen(agent);

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

    /* body is initial counter value (0) */

    RHO_TRACE_EXIT();
}

static int
tcad_cmp_and_get(struct tcad_client *client, const char *name,
        int expected_count, void *data, size_t &data_len)
{
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct rpc_hdr *hdr = &agent->ra_hdr;

    RHO_TRACE_ENTER();

    /* build request */
    rpc_agent_new_msg(agent, TCAD_OP_CMP_AND_GET);
    rho_buf_write_u32size_str(buf, purl->path);
    rho_buf_write32be(buf, expected_count); 
    rpc_agent_autoset_bodylen(agent);

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

    rho_buf_read_u32size_blob(buf, data, 256, &tlen);

    RHO_TRACE_EXIT();
}

static int
tcad_inc_and_set(struct tcad_client *client, const char *name, void *data,
        size_t data_len)
{
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct rpc_hdr *hdr = &agent->ra_hdr;

    RHO_TRACE_ENTER();

    /* build request */
    rpc_agent_new_msg(agent, TCAD_OP_INC_AND_SET);
    rho_buf_write_u32size_str(buf, purl->path);
    rho_buf_write_u32size_blob(buf, data, data_len);
    rpc_agent_autoset_bodylen(agent);

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

    /* no body */

    RHO_TRACE_EXIT();
}

static int
tcad_disconnect(struct tcad_client *client)
{
    RHO_TRACE_ENTER();

    RHO_TRACE_EXIT();
}

/******************************************
 * Ticket-Lock
 ******************************************/

static struct tl *
tl_create(void)
{
    struct tl *tl = NULL;

    /* this memory will be untrusted */
    tl = mmap(NULL, sizeof(struct tl), PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_SHARED, -1, 0);    
    if (tl == NULL)
        rho_errno_die(errno, "mmap");

    tl->ticket_number = 0;
    tl->turn = 0;

    return (tl);
}

static void
tl_destroy(struct tl *tl)
{
    int error = 0;    
    
    error = munmap(tl, sizeof(*tl));
    if (error == -1)
        rho_errno_warn(errno, "munmap");
}

static void
tl_lock(struct tl *tl)
{
    int my_turn;

    my_turn = rho_atomic_fetch_inc(&tl->ticket_number);
    while (my_turn != tl->turn) { /* spin */ ; }
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
segment_create(const char *path, size_t size)
{
    int error = 0;
    int fd = 0;
    struct segment *seg = NULL;

    fd = open(path, O_RDWR|O_CREAT|O_EXCL, S_IRUSR |S_IWUSR |S_IRGRP|S_IWGRP);
    if (fd == -1)
        rho_errno_die(errno, "open(\"%s\")", path);
    
    error = ftruncate(fd, size);
    if (error == -1)
        rho_errno_die(errno, "fdtruncate(\"%s\", %zu)", path, size);

    seg = rhoL_zalloc(sizeof(*seg));

    seg->file_mem =  mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
            fd, 0);    
    if (seg->file_mem == NULL)
        rho_errno_die(errno, "mmap");

    close(fd);

    seg->size = size;
    seg->priv_mem = rhoL_zalloc(size);
    seg->tl = tl_create();
    memcpy(seg->key, default_key, 32);
    seg->path = rhoL_strdup(path);

    return (seg);
}

static void
segment_destroy(struct segment *seg)
{
    int error = 0;

    rhoL_free(seg->priv_mem);
    error = munmap(seg->file_mem, seg->size);
    if (error == -1)
        rho_errno_warn(errno, "munmap");
    rhoL_free(seg->path);
    tl_destroy(seg->tl);

    rhoL_free(seg);
}

/* decrypt file into private memory */
static void
segment_map_in(struct segment *seg, uint8_t *trusted_tag)
{
    memcpy(seg->priv_mem, seg->file_mem, seg->size);
    decrypt(seg->priv_mem, seg->size, seg->key, seg->iv, seg->tag);

    /* TODO: chck that seg->tag == trusted_tag */
}

/* encrypt private memory to file */
static void
segment_map_out(struct segment *seg)
{
    rho_rand_bytes(seg->iv, IV_SIZE);
    encrypt(seg->priv_mem, seg->size, seg->key, seg->iv, seg->tag);
    memcpy(seg->file_mem, seg->priv_mem, seg->size);
}

/******************************************
 * SECMEM
 ******************************************/

static void
secmem_lock(struct secmem *sm)
{
    TIMER_DECL(timer);

    tl_lock(sm->tl);
timer_start(&timer);
    tcad_cmp_and_get(sm->client, sm->path, sm->tl->turn, data, &data_len);

    /* TODO: parse out data: (iv, tag) */

    segment_map_in(sm->segment, tag);

timer_stop(&timer);
    fprintf(stderr, "time for map in: %f secs\n", timer_get_elapsed(&timer));
}

static void
secmem_unlock(struct secmem *sm)
{ 
    TIMER_DECL(timer);

timer_start(&timer);
    segment_map_out(sm->segment);

    /* TODO: concatenate IV and tag into buffer */
    tcad_inc_and_set(sm->client, sm->path, data, data_len);

timer_stop(&timer);
    fprintf(stderr, "time for map out: %f secs\n", timer_get_elapsed(&timer));

    tl_unlock(sm->tl);
}

/******************************************
 * Example Program
 ******************************************/
int
main(int argc, char *argv[])
{
    int i = 0;
    pid_t pid = 0;
    struct secmem *sm = NULL;
    struct tcad_client *client = NULL;


    (void)argc;
    client = tcad_connect(argv[1]);

    tcad_create_entry(client, "foo", "bar", 3);

    for (i = 0; i < ITERATIONS; i++) {
        secmem_lock(sm);
        rho_hexdump(sm->priv_mem, 16, "parent priv_mem on lock (i=%d)", i);
        memcpy(sm->priv_mem + 8, "AAAAAAAA", 8);
        secmem_unlock(sm);
        //rho_hexdump(sm->priv_mem, 16, "parent priv_mem on unlock (i=%d)", i);
        random_sleep();
    }

    secmem_destroy(sm);
    wait(NULL);

    return (0);
}
