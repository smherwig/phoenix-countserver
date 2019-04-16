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

struct secmem {
    char    *path;
    size_t  size;
    void    *file_mem;
    void    *priv_mem;
    struct  tl *tl;
    uint8_t iv[IV_SIZE];
    uint8_t key[32];
    uint8_t tag[16];
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
 * Secure Memory API
 * (shmcrypt)
 *
 * The tl is in untrusted memory.
 * The key is in trusted memory.
 * ******************************************/
static struct secmem *
secmem_create(const char *path, size_t size)
{
    int error = 0;
    int fd = 0;
    struct secmem *sm = NULL;

    fd = open(path, O_RDWR|O_CREAT|O_EXCL, S_IRUSR |S_IWUSR |S_IRGRP|S_IWGRP);
    if (fd == -1)
        rho_errno_die(errno, "open(\"%s\")", path);
    
    error = ftruncate(fd, size);
    if (error == -1)
        rho_errno_die(errno, "fdtruncate(\"%s\", %zu)", path, size);

    sm = rhoL_zalloc(sizeof(*sm));

    sm->file_mem =  mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
            fd, 0);    
    if (sm->file_mem == NULL)
        rho_errno_die(errno, "mmap");

    close(fd);

    sm->size = size;
    sm->priv_mem = rhoL_zalloc(size);
    sm->tl = tl_create();
    memcpy(sm->key, default_key, 32);
    sm->path = rhoL_strdup(path);

    return (sm);
}

static void
secmem_destroy(struct secmem *sm)
{
    int error = 0;

    rhoL_free(sm->priv_mem);
    error = munmap(sm->file_mem, sm->size);
    if (error == -1)
        rho_errno_warn(errno, "munmap");
    rhoL_free(sm->path);
    tl_destroy(sm->tl);

    rhoL_free(sm);
}

/* decrypt file into private memory */
static void
secmem_map_in(struct secmem *sm)
{
    memcpy(sm->priv_mem, sm->file_mem, sm->size);
    decrypt(sm->priv_mem, sm->size, sm->key, sm->iv, sm->tag);
}

/* encrypt private memory to file */
static void
secmem_map_out(struct secmem *sm)
{
    rho_rand_bytes(sm->iv, IV_SIZE);
    encrypt(sm->priv_mem, sm->size, sm->key, sm->iv, sm->tag);
    memcpy(sm->file_mem, sm->priv_mem, sm->size);
}

static void
secmem_lock(struct secmem *sm)
{
    TIMER_DECL(timer);

    tl_lock(sm->tl);

    timer_start(&timer);
    secmem_map_in(sm);
    timer_stop(&timer);
    fprintf(stderr, "time for map in: %f secs\n", timer_get_elapsed(&timer));
}

static void
secmem_unlock(struct secmem *sm)
{ 
    TIMER_DECL(timer);

    timer_start(&timer);
    secmem_map_out(sm);
    timer_stop(&timer);
    fprintf(stderr, "time for map out: %f secs\n", timer_get_elapsed(&timer));

    tl_unlock(sm->tl);
}

/******************************************
 * Example Program
 ******************************************/

static void
random_sleep(void)
{
    int r = 0;

    r = rand() / 10000;
    usleep(r);
}

static void
child(struct secmem *sm)
{
    int i = 0 ;

    for (i = 0; i < ITERATIONS; i++) {
        secmem_lock(sm);
        rho_hexdump(sm->priv_mem, 16, "child priv_mem on lock (i=%d)", i);
        memcpy(sm->priv_mem, "BBBBBBBBBBBBBBBB", 16);
        secmem_unlock(sm);
        //rho_hexdump(sm->priv_mem, 16, "child priv_mem on unlock (i=%d)", i);
        random_sleep();
    }

    secmem_destroy(sm);
}

int
main(int argc, char *argv[])
{
    int i = 0;
    pid_t pid = 0;
    struct secmem *sm = NULL;

    (void)argc;
    (void)argv;

    sm = secmem_create("/tmp/secmem.test", 16);

    pid = fork();
    if (pid == -1)
        rho_errno_die(errno, "fork");

    if (pid == 0) {
        child(sm);
        exit(0);
    }

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
