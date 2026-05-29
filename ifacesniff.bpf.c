/* vmlinux.h dumped from a recent kernel emits a block of kfunc/ksym
 * prototypes (e.g. bpf_stream_vprintk) that collide with the ones in an
 * older bundled bpf_helpers.h. We call no kfuncs, so suppress that block
 * — bpf_helpers.h supplies every helper we use. */
#define BPF_NO_KFUNC_PROTOTYPES

/* The bpftool-generated vmlinux.h emits forward declarations the kernel
 * BTF dump can't fully resolve, which clang flags under -Wall. Harmless
 * — silence them for this header alone, leaving -Wall live below. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* struct __sk_buff comes from vmlinux.h BTF; TC_ACT_OK is a plain macro
 * from pkt_cls.h that never makes it into BTF, so define the one we use. */
#define TC_ACT_OK 0

/* ifacesniff — copy the raw bytes of every packet crossing the attached
 * interface(s) into a ringbuf and hand them to userspace, which renders a
 * tcpdump-style hex dump. The BPF side does no protocol parsing: it grabs
 * the frame from offset 0 (L2 header included on a clsact hook), bounded by
 * a runtime `snaplen`, and tags each event with its ifindex and direction.
 * All decoding happens in JS. */

#define BUFSZ    2048   /* payload buffer per event (power of 2) */
#define LOAD_MAX 0x7ff  /* `cap &= LOAD_MAX` keeps the load size bounded for
                         * the verifier; caps capture at 2047 bytes. */

#define DIR_INGRESS 0
#define DIR_EGRESS  1

/* Runtime knobs, patched from JS via the `.data` section. `enabled` gates
 * emission so userspace can quiesce the tap before unsubscribing;
 * `snaplen` caps how many bytes of each packet are copied to the screen. */
volatile __u32 enabled = 1;
volatile __u32 snaplen = 256;

struct pkt_event {
    __u64 ts;
    __u32 ifindex;
    __u32 wire_len;    /* full on-wire length (skb->len) */
    __u32 cap_len;     /* bytes actually copied into payload */
    __u16 protocol;    /* L3 ethertype, host byte order */
    __u8  direction;
    __u8  _pad;
    __u8  payload[BUFSZ];
};

__attribute__((used)) static const struct pkt_event __pkt_event_anchor;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

/* Reserve an event, fill metadata, and copy up to `snaplen` (clamped to
 * LOAD_MAX) bytes of the frame. The barrier+mask pattern is the only
 * verifier-friendly way to keep the load length both nonzero and bounded
 * by the destination size. */
static __always_inline void emit(struct __sk_buff *skb, __u8 dir)
{
    if (!enabled)
        return;

    struct pkt_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->ts        = bpf_ktime_get_ns();
    e->ifindex   = skb->ifindex;
    e->wire_len  = skb->len;
    e->protocol  = bpf_ntohs(skb->protocol);
    e->direction = dir;
    e->_pad      = 0;

    __u32 cap = skb->len;
    __u32 sl  = snaplen;
    if (cap > sl)
        cap = sl;
    if (cap > LOAD_MAX)
        cap = LOAD_MAX;
    e->cap_len = cap;

    /* Only the first `cap_len` bytes are ever read by userspace, so the
     * uninitialized tail of `payload` never escapes — skip zeroing it
     * (a full-buffer memset is too large for clang to inline here). */
    barrier_var(cap);
    cap &= LOAD_MAX;
    if (cap && bpf_skb_load_bytes(skb, 0, e->payload, cap) < 0) {
        bpf_ringbuf_discard(e, 0);
        return;
    }

    bpf_ringbuf_submit(e, 0);
}

SEC("tcx/ingress")
int on_ingress(struct __sk_buff *skb)
{
    emit(skb, DIR_INGRESS);
    return TC_ACT_OK;
}

SEC("tcx/egress")
int on_egress(struct __sk_buff *skb)
{
    emit(skb, DIR_EGRESS);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
