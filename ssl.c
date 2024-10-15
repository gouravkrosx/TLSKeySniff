// +build ignore

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "k_ssl.h"

#define SSL3_RANDOM_SIZE 32
#define MASTER_SECRET_MAX_LEN 48
#define EVP_MAX_MD_SIZE 64

// It contains the pid of the application.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} app_pid_map SEC(".maps");

// A helper map to store ssl ctx addresses to be retrieved in uretprobe
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(void *));
    __uint(max_entries, 1024);
} ssl_ctx_addresses SEC(".maps");

// A map storing the mastersecrets obtained by uprobes on OpenSSL
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     // __type(key, __u8[32]);
//     __type(key, u32);
//     __type(value, struct mastersecret_t);
//     __uint(max_entries, 1024);
// } mastersecret_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} mastersecret_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct mastersecret_t);
    __uint(max_entries, 1);
} master_secret_buffer_heap SEC(".maps");

// Struct to hold all the TLS mastersecrets
struct mastersecret_t
{
    s32 version;
    u8 client_random[SSL3_RANDOM_SIZE];
    u8 master_key[MASTER_SECRET_MAX_LEN];

    u32 cipher_id;
    u8 handshake_secret[EVP_MAX_MD_SIZE];
    u8 handshake_traffic_hash[EVP_MAX_MD_SIZE];
    u8 client_app_traffic_secret[EVP_MAX_MD_SIZE];
    u8 server_app_traffic_secret[EVP_MAX_MD_SIZE];
    u8 exporter_master_secret[EVP_MAX_MD_SIZE];
};

SEC("uprobe/ssl_do_handshake")
int uprobe_ssl_do_handshake(struct pt_regs *ctx)
{
    // Reading ssl_st_ptr
    void *ssl_st_ptr = (void *)PT_REGS_PARM1_CORE(ctx);
    if (ssl_st_ptr == 0)
    {
        return 0;
    }

    // Store ssl_st_ptr address in map
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_ctx_addresses, &pid_tgid, &ssl_st_ptr, BPF_ANY);

    return 0;
}

SEC("uretprobe/ssl_do_handshake")
int uretprobe_ssl_do_handshake(struct pt_regs *ctx)
{
    __u64 address;
    __u64 *ssl_session_st_ptr;
    __u64 ssl_session_st_addr;

    // get the mastersecret struct from the percpu array.

    u32 kZero = 0;
    // Only lookup no update because each entry of the map is pre-allocated in the socket_data_event_buffer_heap.
    struct mastersecret_t *mastersecret = bpf_map_lookup_elem(&master_secret_buffer_heap, &kZero);
    if (!mastersecret)
    {
        bpf_printk("[%llu]: unable to allocate memory for data event...", bpf_ktime_get_ns());
        return 0;
    }

    // Reading ssl_st_ptr from ssl_ctx_addresses map
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    void **ssl_st_ptr_ptr = bpf_map_lookup_elem(&ssl_ctx_addresses, &pid_tgid);
    if (ssl_st_ptr_ptr == 0)
    {
        return 0;
    }
    void *ssl_st_ptr = *ssl_st_ptr_ptr;
    if (ssl_st_ptr == 0)
    {
        return 0;
    }
    if (ssl_st_ptr == 0)
    {
        return 0;
    }

    // Reading ssl_st->version
    __u64 *ssl_version_ptr = (__u64 *)(ssl_st_ptr + SSL_ST_VERSION);
    int ret =
        bpf_probe_read_user(&mastersecret->version, sizeof(mastersecret->version), (void *)ssl_version_ptr);
    if (ret)
    {
        return 0;
    }

    // Reading ssl_session_st_ptr
    ssl_session_st_ptr = (__u64 *)(ssl_st_ptr + SSL_ST_SESSION);
    ret = bpf_probe_read_user(&ssl_session_st_addr, sizeof(ssl_session_st_addr), ssl_session_st_ptr);
    if (ret)
    {
        return 0;
    }

    // Reading ssl_session_st->cipher_suite_st
    __u64 *ssl_cipher_st_ptr = (__u64 *)(ssl_session_st_addr + SSL_SESSION_ST_CIPHER);

    // get cipher_suite_st pointer
    ret = bpf_probe_read_user(&address, sizeof(address), ssl_cipher_st_ptr);
    if (ret || address == 0)
    {
        bpf_printk(
            "bpf_probe_read ssl_cipher_st_ptr failed, ret :%d, address:%x\n",
            ret, address);
        // return 0;
        void *cipher_id_ptr =
            (void *)(ssl_session_st_addr + SSL_SESSION_ST_CIPHER_ID);
        ret = bpf_probe_read_user(&mastersecret->cipher_id, sizeof(mastersecret->cipher_id), cipher_id_ptr);
        if (ret)
        {
            return 0;
        }
    }
    else
    {
        void *cipher_id_ptr = (void *)(address + SSL_CIPHER_ST_ID);
        ret = bpf_probe_read_user(&mastersecret->cipher_id, sizeof(mastersecret->cipher_id), cipher_id_ptr);
        if (ret)
        {
            return 0;
        }
    }

    // // Reading ssl_st->s3.client_random
    // void *client_random_ptr = (__u64 *)(ssl_st_ptr + SSL_ST_S3_CLIENT_RANDOM);
    // ret = bpf_probe_read_user(&client_random, sizeof(client_random), client_random_ptr);
    // if (ret)
    // {
    //     return 0;
    // }


  u64 *ssl_client_random_ptr = (u64 *)(ssl_st_ptr + SSL_ST_S3_CLIENT_RANDOM);
    // get SSL_ST_S3_CLIENT_RANDOM
    unsigned char client_random[SSL3_RANDOM_SIZE];
    ret = bpf_probe_read_user(&client_random, sizeof(client_random), (void *)ssl_client_random_ptr);
    if (ret) {
        bpf_printk("bpf_probe_read_user failed while reading client_random\n");
        return 0;
    }
    bpf_printk("client_random: %x %x %x\n", client_random[0], client_random[1], client_random[2]);
    ret = bpf_probe_read_kernel(&mastersecret->client_random, sizeof(mastersecret->client_random),
                                (void *)&client_random);
    if (ret) {
        bpf_printk("bpf_probe_read_kernel failed while reading client_random\n");
        return 0;
    }



    // TLS 1.3 master secret

    // Reading handshake secret
    void *hs_ptr_tls13 = (void *)(ssl_st_ptr + SSL_ST_HANDSHAKE_SECRET);
    ret = bpf_probe_read_user(&mastersecret->handshake_secret, sizeof(mastersecret->handshake_secret), (void *)hs_ptr_tls13);
    if (ret)
    {
        return 0;
    }

    // Reading handshake traffic hash
    void *hth_ptr_tls13 = (void *)(ssl_st_ptr + SSL_ST_HANDSHAKE_TRAFFIC_HASH);
    ret = bpf_probe_read_user(&mastersecret->handshake_traffic_hash, sizeof(mastersecret->handshake_traffic_hash), (void *)hth_ptr_tls13);
    if (ret)
    {
        return 0;
    }

    // Reading client application traffic secret
    void *cats_ptr_tls13 =
        (void *)(ssl_st_ptr + SSL_ST_CLIENT_APP_TRAFFIC_SECRET);
    ret = bpf_probe_read_user(&mastersecret->client_app_traffic_secret, sizeof(mastersecret->client_app_traffic_secret), (void *)cats_ptr_tls13);
    if (ret)
    {
        return 0;
    }

    // Reading server application traffic secret
    void *sats_ptr_tls13 =
        (void *)(ssl_st_ptr + SSL_ST_SERVER_APP_TRAFFIC_SECRET);
    ret = bpf_probe_read_user(&mastersecret->server_app_traffic_secret, sizeof(mastersecret->server_app_traffic_secret), (void *)sats_ptr_tls13);
    if (ret)
    {
        return 0;
    }

    // Reading exporter master secret
    void *ems_ptr_tls13 = (void *)(ssl_st_ptr + SSL_ST_EXPORTER_MASTER_SECRET);
    ret = bpf_probe_read_user(&mastersecret->exporter_master_secret, sizeof(mastersecret->exporter_master_secret), (void *)ems_ptr_tls13);
    if (ret)
    {
        return 0;
    }

    // // print all the master key details
    // bpf_printk("Master Secret: %x\n", mastersecret->handshake_secret);
    // bpf_printk("Handshake Traffic Hash: %x\n", mastersecret->handshake_traffic_hash);
    // bpf_printk("Client Application Traffic Secret: %x\n", mastersecret->client_app_traffic_secret);
    // bpf_printk("Server Application Traffic Secret: %x\n", mastersecret->server_app_traffic_secret);
    // bpf_printk("Exporter Master Secret: %x\n", mastersecret->exporter_master_secret);

    bpf_perf_event_output(ctx, &mastersecret_events, BPF_F_CURRENT_CPU, mastersecret, sizeof(struct mastersecret_t));
    // Adding the SSL Key Log entry to the mastersecret map
    // bpf_map_update_elem(&mastersecret_map, &client_random, &mastersecret, BPF_ANY);
    // u32 key = 0;
    // bpf_map_update_elem(&mastersecret_map, &key, &mastersecret, BPF_ANY);

    return 0;
}

// This is important license, DO NOT REMOVE THIS
char _license[] SEC("license") = "GPL";
