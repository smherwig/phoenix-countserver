#ifndef _TCAD_CLIENT_H__
#define _TCAD_CLIENT_H_

#include <rpc.h>

struct tcad_client {
    struct rpc_agent   *cli_agent;
};

struct tcad_client * tcad_connect(const char *url);

int tcad_create_entry(struct tcad_client *client, const char *name,
        void *data, size_t data_len);

int tcad_cmp_and_get(struct tcad_client *client, const char *name,
        int expected_count, void *data, size_t &data_len);

int tcad_inc_and_set(struct tcad_client *client, const char *name,
        void *data, size_t data_len);

int tcad_disconnect(struct tcad_client *client);

#endif /* _TCAD_CLIENT_H_ */
