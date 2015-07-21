#ifndef __NETFILTER_RDR__
#define __NETFILTER_RDR__

#include <dlfcn.h>
#include <assert.h>

static void *nfHandle = NULL;

static inline int InitNF(void)
{
	nfHandle = dlopen("libnetfilter_queue.so", RTLD_NOW);
	if (!nfHandle) {
		return -1;
	}

	return 0;
}

static inline struct nfqnl_msg_packet_hdr* nfq_get_msg_packet_hdr_rdr(struct nfq_data* nfad)
{
	assert(nfHandle);

	static struct nfqnl_msg_packet_hdr* (*nfq_get_msg_packet_hdr_sym)(struct nfq_data*) = NULL;

	if (!nfq_get_msg_packet_hdr_sym) {
		nfq_get_msg_packet_hdr_sym = dlsym(nfHandle, "nfq_get_msg_packet_hdr");
		assert(nfq_get_msg_packet_hdr_sym);
	}

	return nfq_get_msg_packet_hdr_sym(nfad);
}

static inline u_int32_t nfq_get_indev_rdr(struct nfq_data* nfad)
{
	assert(nfHandle);

	static u_int32_t (*nfq_get_indev_sym)(struct nfq_data*) = NULL;

	if (!nfq_get_indev_sym) {
		nfq_get_indev_sym = dlsym(nfHandle, "nfq_get_indev");
		assert(nfq_get_indev_sym);
	}

	return nfq_get_indev_sym(nfad);
}

static inline int nfq_get_timestamp_rdr(struct nfq_data* nfad, struct timeval* tv)
{
	assert(nfHandle);

	static int (*nfq_get_timestamp_sym)(struct nfq_data*, struct timeval*) = NULL;

	if (!nfq_get_timestamp_sym) {
		nfq_get_timestamp_sym = dlsym(nfHandle, "nfq_get_timestamp");
		assert(nfq_get_timestamp_sym);
	}

	return nfq_get_timestamp_sym(nfad, tv);
}

static inline int nfq_get_payload_rdr(struct nfq_data* nfad, char** data)
{
	assert(nfHandle);

	static int (*nfq_get_payload_sym)(struct nfq_data*, char**) = NULL;

	if (!nfq_get_payload_sym) {
		nfq_get_payload_sym = dlsym(nfHandle, "nfq_get_payload");
		assert(nfq_get_payload_sym);
	}

	return nfq_get_payload_sym(nfad, data);
}

static inline struct nfq_q_handle* nfq_create_queue_rdr(struct nfq_handle* h, u_int16_t num, nfq_callback* cb, void* data)
{
	assert(nfHandle);

	static struct nfq_q_handle* (*nfq_create_queue_sym)(struct nfq_handle*, u_int16_t, nfq_callback*, void*) = NULL;

	if (!nfq_create_queue_sym) {
		nfq_create_queue_sym = dlsym(nfHandle, "nfq_create_queue");
		assert(nfq_create_queue_sym);
	}

	return nfq_create_queue_sym(h, num, cb, data);
}

static inline int nfq_handle_packet_rdr(struct nfq_handle* h, char* buf, int len)
{
	assert(nfHandle);

	static int (*nfq_handle_packet_sym)(struct nfq_handle*, char*, int) = NULL;

	if (!nfq_handle_packet_sym) {
		nfq_handle_packet_sym = dlsym(nfHandle, "nfq_handle_packet");
		assert(nfq_handle_packet_sym);
	}

	return nfq_handle_packet_sym(h, buf, len);
}

static inline int nfq_bind_pf_rdr(struct nfq_handle* h, u_int16_t pf)
{
	assert(nfHandle);

	static int (*nfq_bind_pf_sym)(struct nfq_handle*, u_int16_t) = NULL;

	if (!nfq_bind_pf_sym) {
		nfq_bind_pf_sym = dlsym(nfHandle, "nfq_bind_pf");
		assert(nfq_bind_pf_sym);
	}

	return nfq_bind_pf_sym(h, pf);
}

static inline int nfq_fd_rdr(struct nfq_handle* h)
{
	assert(nfHandle);

	static int (*nfq_fd_sym)(struct nfq_handle*) = NULL;

	if (!nfq_fd_sym) {
		nfq_fd_sym = dlsym(nfHandle, "nfq_fd");
		assert(nfq_fd_sym);
	}

	return nfq_fd_sym(h);
}

static inline struct nfq_handle* nfq_open_rdr(void)
{
	assert(nfHandle);

	static struct nfq_handle* (*nfq_open_sym)(void) = NULL;

	if (!nfq_open_sym) {
		nfq_open_sym = dlsym(nfHandle, "nfq_open");
		assert(nfq_open_sym);
	}

	return nfq_open_sym();
}

static inline int nfq_set_queue_maxlen_rdr(struct nfq_q_handle* qh, u_int32_t queuelen)
{
	assert(nfHandle);

	static int (*nfq_set_queue_maxlen_sym)(struct nfq_q_handle*, u_int32_t) = NULL;

	if (!nfq_set_queue_maxlen_sym) {
		nfq_set_queue_maxlen_sym = dlsym(nfHandle, "nfq_set_queue_maxlen");
		assert(nfq_set_queue_maxlen_sym);
	}

	return nfq_set_queue_maxlen_sym(qh, queuelen);
}

static inline int nfq_unbind_pf_rdr(struct nfq_handle* h, u_int16_t pf)
{
	assert(nfHandle);

	static int (*nfq_unbind_pf_sym)(struct nfq_handle*, u_int16_t) = NULL;

	if (!nfq_unbind_pf_sym) {
		nfq_unbind_pf_sym = dlsym(nfHandle, "nfq_unbind_pf");
		assert(nfq_unbind_pf_sym);
	}

	return nfq_unbind_pf_sym(h, pf);
}

static inline int nfq_set_verdict_rdr(struct nfq_q_handle* qh, u_int32_t id, u_int32_t verdict, u_int32_t data_len, const unsigned char* buf)
{
	assert(nfHandle);

	static int (*nfq_set_verdict_sym)(struct nfq_q_handle*, u_int32_t, u_int32_t, u_int32_t, const unsigned char*) = NULL;

	if (!nfq_set_verdict_sym) {
		nfq_set_verdict_sym = dlsym(nfHandle, "nfq_set_verdict");
		assert(nfq_set_verdict_sym);
	}

	return nfq_set_verdict_sym(qh, id, verdict, data_len, buf);
}

static inline int nfq_close_rdr(struct nfq_handle* h)
{
	assert(nfHandle);

	static int (*nfq_close_sym)(struct nfq_handle*) = NULL;

	if (!nfq_close_sym) {
		nfq_close_sym = dlsym(nfHandle, "nfq_close");
		assert(nfq_close_sym);
	}

	return nfq_close_sym(h);
}

static inline int nfq_destroy_queue_rdr(struct nfq_q_handle* qh)
{
	assert(nfHandle);

	static int (*nfq_destroy_queue_sym)(struct nfq_q_handle*) = NULL;

	if (!nfq_destroy_queue_sym) {
		nfq_destroy_queue_sym = dlsym(nfHandle, "nfq_destroy_queue");
		assert(nfq_destroy_queue_sym);
	}

	return nfq_destroy_queue_sym(qh);
}

static inline int nfq_set_mode_rdr(struct nfq_q_handle* qh, u_int8_t mode, u_int32_t range)
{
	assert(nfHandle);

	static int (*nfq_set_mode_sym)(struct nfq_q_handle*, u_int8_t, u_int32_t) = NULL;

	if (!nfq_set_mode_sym) {
		nfq_set_mode_sym = dlsym(nfHandle, "nfq_set_mode");
		assert(nfq_set_mode_sym);
	}

	return nfq_set_mode_sym(qh, mode, range);
}

static inline int nfq_set_queue_flags_rdr(struct nfq_q_handle* qh, uint32_t mask, uint32_t flags)
{
	assert(nfHandle);

	static int (*nfq_set_queue_flags_sym)(struct nfq_q_handle*, uint32_t, uint32_t) = NULL;

	if (!nfq_set_queue_flags_sym) {
		nfq_set_queue_flags_sym = dlsym(nfHandle, "nfq_set_queue_flags");
		assert(nfq_set_queue_flags_sym);
	}

	return nfq_set_queue_flags_sym(qh, mask, flags);
}

#endif //__NETFILTER_RDR__

