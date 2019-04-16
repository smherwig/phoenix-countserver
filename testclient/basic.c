struct tcad_client *
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

int
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

int
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

int
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

int
tcad_disconnect(struct tcad_client *client)
{
    RHO_TRACE_ENTER();

    RHO_TRACE_EXIT();
}
