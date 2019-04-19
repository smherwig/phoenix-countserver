Overview
========

The phoenix-countserver is a trusted monotonic counter server for the Phoenix
SGX microkernel (based on Graphene-SGX).  The server is a key-value store that
maps a name to a tuple `(counter, data)`, where `data` is optional data
that the client associates with the counter.

Counter-entries are capabilities in the sense that a client can only create
entries and child-clients (processes) inherit them; a child process cannot
access an entry that it either didn't created or did not inherit.  This may
change in the future depending on the use-cases that come up.


Protocol
========

The RPC protocol is a simple operation-bodylength-body scheme, where the
operation and bodylength are the header, and body is the RPC payload.  For
requests, operation specifies the RPC function; for responese, `operation` is
instead the `status` of the request (e.g., success, failure).  `status` is
always 0 on success or an Linux errno value on failure.

RPCs always use big-endian integers.  A `bytearray` is an array of bytes.
ASCII strings are sent as a `u32` length followed by a `bytearray`; the
`bytearray` does not include the nul terminator.

The protocol has the following RPCs:


`create_entry`
--------------

Create a new counter-entry.  The entry's initial counter value is always `0`.

### Request

```
Header:
    u32         op_code     0
    u32         body_size
Body:
    u32         name_len
    bytearray   name
    u32         data_size
    bytearray   data
```

`name` is the name of the entry to create, and `data` is any associated data to
associate with the counter.  If the client does not wish to associate data,
then `data_size` is 0.


### Response

If the entry was created, `status` is `0`; the body is the client's 
file descriptor for that entry.

```
Header:
    u32         status      
    u32         body_size    4
Body:
    i32         fd
```

If the entry was not created, `status` is non-zero.  If there was an RPC error,
status is `EPROTO`; if the entry already exists, status is `EEXIST`.

```
Header:
    u32         status      
    u32         body_size    0
```


`destroy_entry`
--------------

Destroy an existing counter-entry.

### Request

```
Header:
    u32         op_code     1
    u32         body_size
Body:
    i32         fd
```


### Response

The response is only a header; if the entry was destroy, `status` is
`0`; if the entry could not be created,  `status` is non-zero: either `EPROTO`
for an RPC error or `EBADF` if the `fd` is invalid.

```
Header:
    u32         status      
    u32         body_size    0
```


`cmp_and_get`
-------------
The client presents what they think the counter is; if this value equals the
current value of the counter, then the data associated with the value is
returned; otherwise, an error is returned.  

### Request

```
Header:
    u32         op_code     2
    u32         body_size
Body:
    u32         fd
    i32         expected_counter
```

If `expected_counter` matches the entrie's counter, the server returns:

```
Header:
    u32         status      0
    u32         body_size
Body:
    u32         data_size
    bytearray   data
```

Otherwise, the server returns:

```
Header:
    u32         status      
    u32         body_size    0
```

On error, the possible value for `status` are:

- `EPROTO`
    The RPC request was malformed
- `EBADF`
    Invalid `fd`
- `EINVAL`
    `expected_counter` does not match the entry's counter



`inc_and_set`
-------------
Increments the 


`fork`
-------

`child_attach`
--------------

`new_fdtable`
-------------

