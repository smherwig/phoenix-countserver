#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rho/rho.h>
#include <rpc.h>

#include <tcad.h>

/**************************************
 * tcadserver -- trusted (incrementing)
 * counter and associated data server
 **************************************/

struct tcad_server {
    struct rho_sock *srv_sock;
    struct rho_ssl_ctx *srv_sc;
    /* TODO: don't hardcode 108 */
    uint8_t srv_udspath[108];
};

struct tcad_entry {
    char    te_name[TCAD_MAX_NAME_SIZE];
    int     te_counter; 
    void    *te_data;
    size_t  te_data_len;
    int     te_refcnt;
    RHO_RB_ENTRY(tcad_entry) te_entry;
};

RHO_RB_HEAD(tcad_entry_tree, tcad_entry);

struct tcad_fdtable {
    struct rho_bitmap *ft_map;   /* bitmap of which fd's have been allocated */
    struct tcad_entry **ft_openentries; /* array of pointers to open entrys; */
};

struct tcad_client {
    RHO_LIST_ENTRY(tcad_client) cli_next_client;
    struct rpc_agent *cli_agent;
    struct tcad_fdtable *cli_fdtab;
    uint64_t cli_id;
};

/* 
 * defines: struct tcad_client_list; 
 * (head of list of clients)
 */
RHO_LIST_HEAD(tcad_client_list, tcad_client); 

typedef void (*tcad_opcall)(struct tcad_client *client);


/**************************************
 * FORWARD DECLARATIONS
 **************************************/
static int tcad_entry_cmp(struct tcad_entry *a, struct tcad_entry *b);

RHO_RB_PROTOTYPE_STATIC(tcad_entry_tree, tcad_entry, te_name, tcad_entry_cmp);

static struct tcad_entry * tcad_entry_create(const char *name, void *data,
        size_t data_len);

static void tcad_entry_destroy(struct tcad_entry *entry);

static void tcad_create_entry_proxy(struct tcad_client *client);
static void tcad_destroy_entry_proxy(struct tcad_client *client);
static void tcad_cmp_and_get_proxy(struct tcad_client *client);
static void tcad_inc_and_set_proxy(struct tcad_client *client);

static void tcad_fork_proxy(struct tcad_client *client);
static void tcad_child_attach_proxy(struct tcad_client *client);
static void tcad_new_fdtable_proxy(struct tcad_client *client);

static struct tcad_fdtable * tcad_fdtable_create(void);
static struct tcad_fdtable * tcad_fdtable_copy(
        const struct tcad_fdtable *fdtab);
static void tcad_fdtable_destroy(struct tcad_fdtable *fdtab);
static void tcad_fdtable_expand(struct tcad_fdtable *fdtab);
static int tcad_fdtable_fdalloc(struct tcad_fdtable *fdtab);
static int tcad_fdtable_setopenentry(struct tcad_fdtable *fdtab,
        struct tcad_entry *entry);

static void tcad_client_add(struct tcad_client *client);
static struct tcad_client * tcad_client_find(uint64_t id);

static struct tcad_client * tcad_client_alloc(void);
static struct tcad_client * tcad_client_create(struct rho_sock *sock);
static void tcad_client_destroy(struct tcad_client *client);
static struct tcad_client * tcad_client_fork(struct tcad_client *parent);
static void tcad_client_splice(struct tcad_client *a, struct tcad_client *b);

static void tcad_client_dispatch_call(struct tcad_client *client);
static void tcad_client_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop);

static struct tcad_server * tcad_server_alloc(void);
static void tcad_server_destroy(struct tcad_server *server);
static void tcad_server_config_ssl(struct tcad_server *server,
        const char *cafile, const char *certfile, const char *keyfile);
static void tcad_server_socket_create(struct tcad_server *server,
        const char *udspath, bool anonymous);
static void tcad_server_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop);

static void tcad_log_init(const char *logfile, bool verbose);

static void usage(int exitcode);

/**************************************
 * GLOBALS
 **************************************/

struct rho_log *tcad_log = NULL;

struct tcad_client_list tcad_clients = 
        RHO_LIST_HEAD_INITIALIZER(tcad_clients);

struct tcad_entry_tree tcad_entry_tree_root = 
        RHO_RB_INITIALIZER(&tcad_entry_tree_root);

static tcad_opcall tcad_opcalls[] = {
    [TCAD_OP_CREATE_ENTRY]  = tcad_create_entry_proxy,
    [TCAD_OP_DESTROY_ENTRY] = tcad_destroy_entry_proxy,
    [TCAD_OP_CMP_AND_GET]   = tcad_cmp_and_get_proxy,
    [TCAD_OP_INC_AND_SET]   = tcad_inc_and_set_proxy,

    /* fork/exec */
    [TCAD_OP_FORK]           = tcad_fork_proxy,
    [TCAD_OP_CHILD_ATTACH]   = tcad_child_attach_proxy,
    [TCAD_OP_NEW_FDTABLE]    = tcad_new_fdtable_proxy,
};

/**************************************
 * RED-BLACK TREE OF ENTRIES
 **************************************/

static int
tcad_entry_cmp(struct tcad_entry *a, struct tcad_entry *b)
{
    return (strcmp(a->te_name, b->te_name));
}

RHO_RB_GENERATE_STATIC(tcad_entry_tree, tcad_entry, te_entry, tcad_entry_cmp);

static struct tcad_entry *
tcad_entry_tree_find(const char *name)
{
    size_t n = 0;
    struct tcad_entry key;
    struct tcad_entry *entry = NULL;

    RHO_TRACE_ENTER();

    n = rho_strlcpy(key.te_name, name, TCAD_MAX_NAME_SIZE);
    if (n >= TCAD_MAX_NAME_SIZE) {
        rho_warn("strlcpy truncation would occur\n");
        return (NULL);
    }

    entry = RHO_RB_FIND(tcad_entry_tree, &tcad_entry_tree_root, &key);

    RHO_TRACE_EXIT();
    return (entry);
}

/**************************************
 * ENTRY
 **************************************/

/* assumes ownership of data */
static struct tcad_entry *
tcad_entry_create(const char *name, void *data, size_t data_len)
{
    size_t n = 0;
    struct tcad_entry *entry = NULL;

    RHO_TRACE_ENTER();

    entry = rhoL_zalloc(sizeof(*entry));

    n = rho_strlcpy(entry->te_name, name, sizeof(entry->te_name));
    RHO_ASSERT(n < sizeof(entry->te_name));

    entry->te_data_len = data_len;
    entry->te_data= data;

    RHO_TRACE_EXIT();
    return (entry);
}

static void
tcad_entry_destroy(struct tcad_entry *entry)
{
    RHO_TRACE_ENTER();

    rhoL_free(entry->te_data);
    rhoL_free(entry);

    RHO_TRACE_EXIT();
}

/**************************************
 * RPC HANDLERS
 **************************************/

/**
 * request:
 *  uint32_t name_len
 *  var      name
 *  uint32_t data_len
 *  var      data
 *
 * response:
 *  null body on error
 *  uint32_t initial counter value on success
 */
static void
tcad_create_entry_proxy(struct tcad_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct tcad_fdtable *fdtab = client->cli_fdtab;
    uint32_t name_len;
    char name[TCAD_MAX_NAME_SIZE] = { 0 };
    uint32_t data_len;
    uint8_t *data = NULL;
    struct tcad_entry *entry = NULL;

    RHO_TRACE_ENTER();

    /* name */
    error = rho_buf_readu32be(buf, &name_len);
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    if (name_len >= TCAD_MAX_NAME_SIZE) {
        error = EPROTO;
        goto done;
    }

    if (rho_buf_read(buf, name, name_len) != name_len) {
        error = EPROTO;
        goto done;
    }

    /* value */
    error = rho_buf_readu32be(buf, &data_len);
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    if (data_len > TCAD_MAX_NAME_SIZE) {
        error = EPROTO;
        goto done;
    }

    data = rhoL_malloc(data_len);
    if (rho_buf_read(buf, data, data_len) != data_len) {
        error = EPROTO;
        goto done;
    }

    /* add the entry if it does not already exist */
    entry = tcad_entry_tree_find(name);
    if (entry != NULL) {
        error = EEXIST;
        goto done;
    }

    /* TODO: need to add fd to fdtable */
    entry = tcad_entry_create(name, data, data_len);
    tcad_fdtable_setopenentry(fdtab, entry);
    RHO_RB_INSERT(tcad_entry_tree, &tcad_entry_tree_root, entry);
    error = 0;

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(tcad_log, error, "id=0x%"PRIx64" create_entry()\n");
        if (data != NULL)
            rhoL_free(data);
    } else {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, entry->te_counter);
        rho_log_errno_debug(tcad_log, error,
                "id=0x%"PRIx64" create_entry(name=\"%s\", data_len=%zu) -> counter=%zu",
                client->cli_id, name, data_len, entry->te_counter);
    }
    
    RHO_TRACE_EXIT();
    return;
}

/**
 * request:
 *  uint32_t name_len
 *  var      name
 *
 * response:
 *  successs or failure
 */
static void
tcad_destroy_entry_proxy(struct tcad_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t name_len;
    char name[TCAD_MAX_NAME_SIZE] = { 0 };
    struct tcad_entry *entry = NULL;

    RHO_TRACE_ENTER();

    /* name */
    error = rho_buf_readu32be(buf, &name_len);
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    if (name_len >= TCAD_MAX_NAME_SIZE) {
        error = EPROTO;
        goto done;
    }

    if (rho_buf_read(buf, name, name_len) != name_len) {
        error = EPROTO;
        goto done;
    }

    /* check entry exists */
    entry = tcad_entry_tree_find(name);
    if (entry != NULL) {
        error = EEXIST;
        goto done;
    }

    /* TODO: need to remove fd from fdtable */
    entry->te_refcnt--;
    if (entry->te_refcnt == 0) {
        RHO_RB_REMOVE(tcad_entry_tree, &tcad_entry_tree_root, entry);
        tcad_entry_destroy(entry);
    }

    error = 0;

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(tcad_log, error, "id=0x%"PRIx64" destroy_entry()\n");
    } else {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, entry->te_counter);
        rho_log_errno_debug(tcad_log, error,
                "id=0x%"PRIx64" destroy_entry(name=\"%s\")",
                client->cli_id, name);
    }
    
    RHO_TRACE_EXIT();
    return;
}

/*
 * Request:
 *  uint32_t name_len
 *  var      name
 *  int32_t  expected_counter value
 *
 * Response:
 *  if expected_counter == counter:
 *      return (success, value)
 *  else:
 *      return (failure)
 */
static void
tcad_cmp_and_get_proxy(struct tcad_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t name_len;
    char name[TCAD_MAX_NAME_SIZE] = { 0 };
    int32_t expected_counter = 0;
    struct tcad_entry *entry = NULL;

    RHO_TRACE_ENTER();

    /* name */
    error = rho_buf_readu32be(buf, &name_len);
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    if (name_len >= TCAD_MAX_NAME_SIZE) {
        error = EPROTO;
        goto done;
    }

    if (rho_buf_read(buf, name, name_len) != name_len) {
        error = EPROTO;
        goto done;
    }

    /* expected counter */
    error = rho_buf_read32be(buf, &expected_counter);
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    /* get entry */
    entry = tcad_entry_tree_find(name);
    if (entry == NULL) {
        error = ENOENT;
        goto done;
    }

    if (entry->te_counter != expected_counter) {
        error = EINVAL;
        goto done;
    }

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(tcad_log, error, "id=0x%"PRIx64" cmp_and_get()\n");
    } else {
        rpc_agent_set_bodylen(agent, 4 + entry->te_data_len);
        rho_buf_writeu32be(buf, entry->te_data_len);
        rho_buf_write(buf, entry->te_data, entry->te_data_len);
        rho_log_errno_debug(tcad_log, error,
                "id=0x%"PRIx64" cmp_and_get(name=\"%s\")",
                client->cli_id, name);
    }
    
    RHO_TRACE_EXIT();
    return;
}

/**
 * Request:
 *  uint32_t name_len
 *  var      name
 *  uint32_t data_len
 *  var      data
 *
 * Response:
 *  either an error code or success code
 *  (there is no msg body)
 *
 */
static void
tcad_inc_and_set_proxy(struct tcad_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t name_len;
    char name[TCAD_MAX_NAME_SIZE] = { 0 };
    uint32_t data_len;
    uint8_t *data = NULL;
    struct tcad_entry *entry = NULL;

    RHO_TRACE_ENTER();

    /* name */
    error = rho_buf_readu32be(buf, &name_len);
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    if (name_len >= TCAD_MAX_NAME_SIZE) {
        error = EPROTO;
        goto done;
    }

    if (rho_buf_read(buf, name, name_len) != name_len) {
        error = EPROTO;
        goto done;
    }

    /* value */
    error = rho_buf_readu32be(buf, &data_len);
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    if (data_len > TCAD_MAX_NAME_SIZE) {
        error = EPROTO;
        goto done;
    }

    data = rhoL_malloc(data_len);
    if (rho_buf_read(buf, data, data_len) != data_len) {
        error = EPROTO;
        goto done;
    }

    entry = tcad_entry_tree_find(name);
    if (entry == NULL) {
        error = ENOENT;
        goto done;
    }


    /* TODO: avoid the memcpy */
    if (data_len > entry->te_data_len)
        rhoL_realloc(entry->te_data, data_len);
    memcpy(entry->te_data, data, data_len);
    entry->te_data_len = data_len;
    entry->te_counter++;
    error = 0;

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(tcad_log, error, "id=0x%"PRIx64" inc_and_set()\n");
        if (data != NULL)
            rhoL_free(data);
    } else {
        rho_log_errno_debug(tcad_log, error,
                "id=0x%"PRIx64" inc_and_set(name=\"%s\", data_len=%zu)",
                client->cli_id, name, data_len);
    }
    if (data != NULL)
        rhoL_free(data);
    
    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * FORK/EXEC RPCs
 **************************************/

/*
 * RPC invoked by parent.
 * Create a tcad_cilent state for child, and return the child's id.
 */
static void
tcad_fork_proxy(struct tcad_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct tcad_client *child = NULL;
    uint64_t id = 0;

    RHO_TRACE_ENTER();

    child = tcad_client_fork(client);
    tcad_client_add(child);
    id = child->cli_id;

    rpc_agent_new_msg(agent, error);
    rpc_agent_set_bodylen(agent, 8);
    rho_buf_writeu64be(buf, id);

    rho_log_errno_debug(tcad_log, error, "id=0x%"PRIx64" fork() -> 0x%"PRIx64,
        client->cli_id, id);

    RHO_TRACE_EXIT();
}

/*
 * RPC invoked by child.
 * 
 * Find the tcad_client that parent created for the child 
 * when the parent invokded the fork RPC.
 */
static void
tcad_child_attach_proxy(struct tcad_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint64_t id;
    struct tcad_client *attachee = NULL;;

    RHO_TRACE_ENTER();

    error = rho_buf_readu64be(buf, &id);
    if (error == -1) {
        /* 
         * TODO: we might want to replace EPROTO with EREMOTEIO,
         * which, I think, is a non-POSIX errno value that Linux uses
         */
        error = EPROTO;
        goto done;
    }

    attachee = tcad_client_find(id);
    if (attachee == NULL) {
        /* XXX: there might be a more specific errno value for this scenario */
        error = EINVAL;
        goto done;
    }

    tcad_client_splice(client, attachee);
    
done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(tcad_log, error, "id=0x%"PRIx64" child_attach()",
        client->cli_id);

    RHO_TRACE_EXIT();
    return;
}

static void
tcad_new_fdtable_proxy(struct tcad_client *client)
{
    struct rpc_agent *agent = client->cli_agent;

    RHO_TRACE_ENTER();

    if (client->cli_fdtab != NULL)
        tcad_fdtable_destroy(client->cli_fdtab);

    client->cli_fdtab = tcad_fdtable_create();

    rpc_agent_new_msg(agent, 0);

    rho_log_errno_debug(tcad_log, 0, "id=0x%"PRIx64" new_fdtable()",
        client->cli_id);

    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * FDTABLE
 **************************************/

static struct tcad_fdtable *
tcad_fdtable_create(void)
{
    struct tcad_fdtable *fdtab = NULL;

    RHO_TRACE_ENTER();

    fdtab = rhoL_zalloc(sizeof(*fdtab));
    fdtab->ft_map = rho_bitmap_create(true, 20);
    fdtab->ft_openentries = rhoL_mallocarray(20,
            sizeof(struct tcad_entry *), 0);

    RHO_TRACE_EXIT();
    return (fdtab);
}

static void
tcad_fdtable_expand(struct tcad_fdtable *fdtab)
{
    size_t newmaxbits = 0;
    struct rho_bitmap *map = fdtab->ft_map;

    RHO_TRACE_ENTER();
    
    /* TODO: check for overflow; also, check that this actually
     * expands, since the range of size_t is greater than int
     */
    newmaxbits = rho_bitmap_size(map) + 32;
    rho_bitmap_resize(map, newmaxbits);
    fdtab->ft_openentries = rhoL_reallocarray(fdtab->ft_openentries,
            newmaxbits, sizeof(struct tcad_entry), 0);

    RHO_TRACE_EXIT();
}

static struct tcad_fdtable *
tcad_fdtable_copy(const struct tcad_fdtable *fdtab)
{
    struct tcad_fdtable *newp = NULL;
    struct tcad_entry *entry = NULL;
    size_t fd = 0;
    int bitval = 0;
    size_t n = 0;

    RHO_TRACE_ENTER();

    newp = rhoL_zalloc(sizeof(*newp));
    newp->ft_map = rho_bitmap_copy(fdtab->ft_map);

    n = rho_bitmap_size(fdtab->ft_map);
    newp->ft_openentries = rhoL_mallocarray(n, sizeof(struct tcad_entry *), 0);

    RHO_BITMAP_FOREACH(fd, bitval, fdtab->ft_map) {
        if (bitval == 0)
            continue;
        entry = fdtab->ft_openentries[fd];
        entry->te_refcnt++;
        newp->ft_openentries[fd] = entry;
    }

    RHO_TRACE_EXIT();
    return (newp);
}

static void
tcad_fdtable_destroy(struct tcad_fdtable *fdtab)
{
    size_t fd = 0;
    int bitval = 0;
    struct tcad_entry *entry = NULL;

    RHO_TRACE_ENTER();

    RHO_BITMAP_FOREACH(fd, bitval, fdtab->ft_map) {
        if (bitval == 0)
            continue;
        entry = fdtab->ft_openentries[fd];
        entry->te_refcnt--;
        if (entry->te_refcnt == 0) {
            RHO_RB_REMOVE(tcad_entry_tree, &tcad_entry_tree_root, entry);
            tcad_entry_destroy(entry);
        }
    }

    rhoL_free(fdtab->ft_openentries);
    rho_bitmap_destroy(fdtab->ft_map);
    rhoL_free(fdtab);

    RHO_TRACE_EXIT();
    return;
}

/*
 * Allocate a file descriptor for the client.
 */
static int
tcad_fdtable_fdalloc(struct tcad_fdtable *fdtab)
{
    int fd = 0;
    size_t oldmaxbits = 0;
    struct rho_bitmap *map = fdtab->ft_map;

    RHO_TRACE_ENTER();

    /* TODO: you might want some upper limit on how many files a client can
     * have open
     */
    fd = rho_bitmap_ffc(map);
    if (fd == -1) {
        oldmaxbits = rho_bitmap_size(map);
        tcad_fdtable_expand(fdtab);
        fd = oldmaxbits;
    }

    rho_bitmap_set(fdtab->ft_map, fd);

    RHO_TRACE_EXIT("fd=%d", fd);
    return (fd);
}

/*
 * Create and allocate a file descriptor for the
 * client that refers to it.
 */
static int
tcad_fdtable_setopenentry(struct tcad_fdtable *fdtab, struct tcad_entry *entry)
{
    int fd = 0;

    RHO_TRACE_ENTER();

    fd = tcad_fdtable_fdalloc(fdtab);
    fdtab->ft_openentries[fd] = entry;

    RHO_TRACE_EXIT("fd=%d", fd);
    return (fd);
}


/**************************************
 * CLIENT
 **************************************/
static void
tcad_client_add(struct tcad_client *client)
{
    uint64_t id = 0;
    struct tcad_client *iter = NULL;

    RHO_TRACE_ENTER();

    /* find a unique client id */
    do {
again:
        id = rho_rand_u64();
        RHO_LIST_FOREACH(iter, &tcad_clients, cli_next_client) {
            if (iter->cli_id == id)
                goto again;
        }
        break;
    } while (1);

    client->cli_id = id;
    RHO_LIST_INSERT_HEAD(&tcad_clients, client, cli_next_client);

    RHO_TRACE_EXIT();
    return;
}

static struct tcad_client *
tcad_client_find(uint64_t id)
{
    struct tcad_client *iter = NULL;

    RHO_TRACE_ENTER();

    RHO_LIST_FOREACH(iter, &tcad_clients, cli_next_client) {
        if (iter->cli_id == id)
            goto done;
    }

    iter = NULL;

done:
    RHO_TRACE_EXIT();
    return (iter);
}

static struct tcad_client *
tcad_client_alloc(void)
{
    struct tcad_client *client = NULL;

    RHO_TRACE_ENTER();

    client = rhoL_zalloc(sizeof(*client));
    client->cli_agent = rpc_agent_create(NULL, NULL);

    RHO_TRACE_EXIT();
    return (client);
}

static struct tcad_client *
tcad_client_create(struct rho_sock *sock)
{
    struct tcad_client *client = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER();

    client = tcad_client_alloc();
    agent = client->cli_agent;
    agent->ra_sock = sock;

    if (sock->ssl != NULL)
        agent->ra_state = RPC_STATE_HANDSHAKE;
    else
        agent->ra_state = RPC_STATE_RECV_HDR;

    RHO_TRACE_EXIT();
    return (client);
}

static void
tcad_client_destroy(struct tcad_client *client)
{
    RHO_ASSERT(client != NULL);

    RHO_TRACE_ENTER();

    rpc_agent_destroy(client->cli_agent);
    if (client->cli_fdtab != NULL)
        tcad_fdtable_destroy(client->cli_fdtab);
    rhoL_free(client);

    RHO_TRACE_EXIT();
}

static struct tcad_client *
tcad_client_fork(struct tcad_client *parent)
{
    struct tcad_client *client = NULL;

    RHO_TRACE_ENTER();

    client = tcad_client_alloc();
    client->cli_fdtab = tcad_fdtable_copy(parent->cli_fdtab);

    RHO_TRACE_EXIT();
    return (client);
}

/*
 * a is from the child connecing
 * b is from the parent's fork
 *
 * a gets b's filedescriptor table
 * b is deleted
 */
static void
tcad_client_splice(struct tcad_client *a, struct tcad_client *b)
{
    RHO_TRACE_ENTER();

    a->cli_fdtab = b->cli_fdtab;
    b->cli_fdtab = NULL;

    RHO_LIST_REMOVE(b, cli_next_client);
    tcad_client_destroy(b);

    RHO_TRACE_EXIT();
    return;
};

static void
tcad_client_dispatch_call(struct tcad_client *client)
{
    struct rpc_agent *agent = client->cli_agent;
    uint32_t opcode = agent->ra_hdr.rh_code;
    tcad_opcall opcall = NULL;

    RHO_ASSERT(agent->ra_state == RPC_STATE_DISPATCHABLE);
    RHO_ASSERT(rho_buf_tell(agent->ra_bodybuf) == 0);

    RHO_TRACE_ENTER("fd=%d, opcode=%d", agent->ra_sock->fd, opcode);

    if (opcode >= RHO_C_ARRAY_SIZE(tcad_opcalls)) {
        rho_log_warn(tcad_log, "bad opcode (%"PRIu32")", opcode);
        rpc_agent_new_msg(agent, ENOSYS);
        goto done;
    } 

    opcall = tcad_opcalls[opcode];
    opcall(client);

done:
    rpc_agent_ready_send(agent);
    RHO_TRACE_EXIT();
    return;
}

static void
tcad_client_cb(struct rho_event *event, int what, struct rho_event_loop *loop)
{
    int ret = 0;
    struct tcad_client *client = NULL;
    struct rpc_agent *agent = NULL;

    RHO_ASSERT(event != NULL);
    RHO_ASSERT(event->userdata != NULL);
    RHO_ASSERT(loop != NULL);

    (void)what;

    client = event->userdata;
    agent = client->cli_agent;

    RHO_TRACE_ENTER("fd=%d, what=%08x, state=%s",
            event->fd,
            what,
            rpc_state_to_str(agent->ra_state));
            
    if (agent->ra_state == RPC_STATE_HANDSHAKE) {
        ret = rho_ssl_do_handshake(agent->ra_sock);
        rho_debug("rho_ssl_do_handshake returned %d", ret);
        if (ret == 0) {
            /* ssl handshake complete */
            agent->ra_state  = RPC_STATE_RECV_HDR;
            event->flags = RHO_EVENT_READ;
            goto again;
        } else if (ret == 1) {
            /* ssl handshake still in progress: want_read */
            event->flags = RHO_EVENT_READ;
            goto again;
        } else if (ret == 2) {
            /* ssl handshake still in progress: want_write */
            event->flags = RHO_EVENT_WRITE;
            goto again;
        } else {
            /* an error occurred during the handshake */
            agent->ra_state = RPC_STATE_ERROR; /* not needed */
            goto done;
        }
    }

    if (agent->ra_state == RPC_STATE_RECV_HDR)
        rpc_agent_recv_hdr(agent);

    if (agent->ra_state == RPC_STATE_RECV_BODY) 
        rpc_agent_recv_body(agent);

    if (agent->ra_state == RPC_STATE_DISPATCHABLE)
        tcad_client_dispatch_call(client);

    if (agent->ra_state == RPC_STATE_SEND_HDR)
        rpc_agent_send_hdr(agent);

    if (agent->ra_state == RPC_STATE_SEND_BODY)
        rpc_agent_send_body(agent);

    if ((agent->ra_state == RPC_STATE_ERROR) ||
            (agent->ra_state == RPC_STATE_CLOSED)) {
        goto done;
    }

again:
    rho_event_loop_add(loop, event, NULL); 
    RHO_TRACE_EXIT("reschedule callback; state=%s", 
            rpc_state_to_str(agent->ra_state));
    return;

done:
    RHO_LIST_REMOVE(client, cli_next_client);
    rho_log_info(tcad_log, "id=0x%"PRIx64" disconnected", client->cli_id);
    tcad_client_destroy(client);
    RHO_TRACE_EXIT("client done");
    return;
}

/**************************************
 * SERVER
 **************************************/
static struct tcad_server *
tcad_server_alloc(void)
{
    struct tcad_server *server = NULL;
    server = rhoL_zalloc(sizeof(*server));
    return (server);
}

static void
tcad_server_destroy(struct tcad_server *server)
{
    int error = 0;

    if (server->srv_sock != NULL) {
        if (server->srv_udspath[0] != '\0') {
            error = unlink((const char *)server->srv_udspath);
            if (error != 0)
                rho_errno_warn(errno, "unlink('%s') failed", server->srv_udspath);
        }
        rho_sock_destroy(server->srv_sock);
    }

    rhoL_free(server);
}

static void
tcad_server_config_ssl(struct tcad_server *server,
        const char *cafile, const char *certfile, const char *keyfile)
{
    struct rho_ssl_params *params = NULL;
    struct rho_ssl_ctx *sc = NULL;

    RHO_TRACE_ENTER("cafile=%s, certfile=%s, keyfile=%s",
            cafile, certfile, keyfile);

    params = rho_ssl_params_create();
    rho_ssl_params_set_mode(params, RHO_SSL_MODE_SERVER);
    rho_ssl_params_set_protocol(params, RHO_SSL_PROTOCOL_TLSv1_2);
    rho_ssl_params_set_private_key_file(params, keyfile);
    rho_ssl_params_set_certificate_file(params, certfile);
    rho_ssl_params_set_ca_file(params, cafile);
    //rho_ssl_params_set_verify(params, true);
    rho_ssl_params_set_verify(params, false);
    sc = rho_ssl_ctx_create(params);
    server->srv_sc = sc;
    rho_ssl_params_destroy(params);

    RHO_TRACE_EXIT();
}

static void
tcad_server_socket_create(struct tcad_server *server, const char *udspath,
        bool anonymous)
{
    size_t pathlen = 0;
    struct rho_sock *sock = NULL;

    pathlen = strlen(udspath) + 1;
    if (anonymous) {
        strcpy((char *)(server->srv_udspath + 1), udspath);
        pathlen += 1;
    } else {
        strcpy((char *)server->srv_udspath, udspath);
    }
    
    sock = rho_sock_unixserver_create(server->srv_udspath, pathlen, 5);
    rho_sock_setnonblocking(sock);
    server->srv_sock = sock;
}

static void
tcad_server_cb(struct rho_event *event, int what, struct rho_event_loop *loop)
{
    int cfd = 0;
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);
    struct rho_event *cevent = NULL;
    struct tcad_client *client = NULL;
    struct tcad_server *server = NULL;
    struct rho_sock *csock = NULL;

    RHO_ASSERT(event != NULL);
    RHO_ASSERT(loop != NULL);
    RHO_ASSERT(event->userdata != NULL);
    server = event->userdata;

    (void)what;
    //fprintf(stderr, "server callback (fd=%d, what=%08x)\n", event->fd, what);

    cfd = accept(event->fd, (struct sockaddr *)&addr, &addrlen);
    if (cfd == -1)
        rho_errno_die(errno, "accept failed");
    /* TODO: check that addrlen == sizeof struct soackaddr_un */

    csock = rho_sock_unix_from_fd(cfd);
    rho_sock_setnonblocking(csock);
    if (server->srv_sc != NULL)
        rho_ssl_wrap(csock, server->srv_sc);
    client = tcad_client_create(csock);
    tcad_client_add(client);
    rho_log_info(tcad_log, "new connection: id=0x%"PRIx64, client->cli_id);
    /* 
     * XXX: do we have a memory leak with event -- where does it get destroyed?
     */
    cevent = rho_event_create(cfd, RHO_EVENT_READ, tcad_client_cb, client);
    client->cli_agent->ra_event = cevent;
    rho_event_loop_add(loop, cevent, NULL); 
}


/**************************************
 * LOG
 **************************************/
static void
tcad_log_init(const char *logfile, bool verbose)
{
    int fd = STDERR_FILENO;

    RHO_TRACE_ENTER();

    if (logfile != NULL) {
        fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT,
                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH,S_IWOTH);
        if (fd == -1)
            rho_errno_die(errno, "can't open or creat logfile \"%s\"", logfile);
    }

    tcad_log = rho_log_create(fd, RHO_LOG_INFO, rho_log_default_writer, NULL);

    if (verbose) 
        rho_log_set_level(tcad_log, RHO_LOG_DEBUG);

    if (logfile != NULL) {
        rho_log_redirect_stderr(tcad_log);
        (void)close(fd);
    }

    RHO_TRACE_EXIT();
}


#define TCADSERVER_USAGE \
    "usage: tcadserver [options] UDSPATH\n" \
    "\n" \
    "OPTIONS:\n" \
    "   -a\n" \
    "       Treat UDSPATH as an abstract socket\n" \
    "       (adds a leading nul byte to UDSPATH)\n" \
    "\n" \
    "   -d\n" \
    "       Daemonize\n" \
    "\n" \
    "   -h\n" \
    "       Show this help message and exit\n" \
    "\n" \
    "   -l LOG_FILE\n" \
    "       Log file to use.  If not specified, logs are printed to stderr.\n" \
    "       If specified, stderr is also redirected to the log file.\n" \
    "\n" \
    "   -v\n" \
    "       Verbose logging.\n" \
    "\n" \
    "   -Z  CACERT CERT PRIVKEY\n" \
    "       Sets the path to the server certificate file and private key\n" \
    "       in PEM format.  This also causes the server to start SSL mode\n" \
    "\n" \
    "\n" \
    "ARGUMENTS:\n" \
    "   UDSPATH\n" \
    "       The path to the UNIX domain socket to listen to connections on\n"

static void
usage(int exitcode)
{
    fprintf(stderr, "%s\n", TCADSERVER_USAGE);
    exit(exitcode);
}

int
main(int argc, char *argv[])
{
    int c = 0;
    struct tcad_server *server = NULL;
    struct rho_event *event = NULL;
    struct rho_event_loop *loop = NULL;
    /* options */
    bool anonymous = false;
    bool daemonize  = false;
    const char *logfile = NULL;
    bool verbose = false;

    rho_ssl_init();

    server = tcad_server_alloc();
    while ((c = getopt(argc, argv, "ab:dhl:vZ:")) != -1) {
        switch (c) {
        case 'a':
            anonymous = true;
            break;
        case 'd':
            daemonize = true;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case 'l':
            logfile = optarg;
            break;
        case 'v':
            verbose = true;
            break;
        case 'Z':
            /* make sure there's three arguments */
            if ((argc - optind) < 2)
                usage(EXIT_FAILURE);
            tcad_server_config_ssl(server, optarg, argv[optind], argv[optind + 1]);
            optind += 2;
            break;
        default:
            usage(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc != 1)
        usage(EXIT_FAILURE);

    if (daemonize)
        rho_daemon_daemonize(NULL, 0);

    tcad_log_init(logfile, verbose);
    tcad_server_socket_create(server, argv[0], anonymous);

    event = rho_event_create(server->srv_sock->fd, RHO_EVENT_READ | RHO_EVENT_PERSIST, 
            tcad_server_cb, server); 

    loop = rho_event_loop_create();
    rho_event_loop_add(loop, event, NULL); 
    rho_event_loop_dispatch(loop);

    /* TODO: destroy event and event_loop */

    tcad_server_destroy(server);
    rho_ssl_fini();

    return (0);
}
