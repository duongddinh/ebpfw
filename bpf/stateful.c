/* SPDX-License-Identifier: GPL-2.0-only */
/* Full policy enforcement is eBPF. Netfilter supplies packet-path hooks and
 * IP reassembly, not nftables rules or Netfilter connection tracking. */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef int s32;
typedef long long s64;
#pragma clang diagnostic ignored "-Wunused-variable"
#define SEC(s) __attribute__((section(s),used))
#define __uint(n,v) int (*n)[v]
#define __type(n,v) v *n
#define __array(n,v) v *n[]
#define INLINE static __inline __attribute__((always_inline))
#define CORE __attribute__((preserve_access_index))
#define MAP(name,kind,key_t,val_t,entries) struct { __uint(type,kind); __uint(max_entries,entries); __type(key,key_t); __type(value,val_t); } name SEC(".maps")
struct net_device { int ifindex; char name[16]; } CORE;
struct sk_buff { u32 len; } CORE;
struct nf_hook_state { u8 hook; u8 pf; struct net_device *in; struct net_device *out; } CORE;
struct bpf_nf_ctx { const struct nf_hook_state *state; struct sk_buff *skb; };
struct bpf_dynptr { u64 opaque[2]; };
struct bpf_spin_lock { u32 val; };
static void *(*map_lookup)(void *,const void *)=(void *)1;
static long (*map_update)(void *,const void *,const void *,u64)=(void *)2;
static long (*map_delete)(void *,const void *)=(void *)3;
static u64 (*ktime_ns)(void)=(void *)5;
static long (*probe_read)(void *,u32,const void *)=(void *)113;
static long (*dyn_read)(void *,u32,const struct bpf_dynptr *,u32,u64)=(void *)201;
static long (*bpf_loop)(u32,void *,void *,u64)=(void *)181;
static void (*spin_lock)(struct bpf_spin_lock *)=(void *)93;
static void (*spin_unlock)(struct bpf_spin_lock *)=(void *)94;
static void *(*ring_reserve)(void *,u64,u64)=(void *)131;
static void (*ring_submit)(void *,u64)=(void *)132;
struct __sk_buff { u32 len; };
extern int bpf_dynptr_from_skb(struct __sk_buff *,u64,struct bpf_dynptr *) __attribute__((section(".ksyms")));

#define MAX_RULES 16384
#define RULE_SIZE 96
#define NS 1000000000ULL
#define ALLOW 1
#define DENY 2
#define REJECT 3
#define LIMIT 4
#define BLOCK 5
#define IN 1
#define OUT 2
#define ROUTE 3
#define STAT_DEFAULT (MAX_RULES+0)
#define STAT_STATE (MAX_RULES+3)
#define STAT_INVALID (MAX_RULES+4)
#define STAT_CT_FULL (MAX_RULES+5)
#define STAT_EVENT_LOST (MAX_RULES+6)
#define STAT_RATE (MAX_RULES+7)
#define STAT_PASS (MAX_RULES+8)
#define STAT_DROP (MAX_RULES+9)
#define STAT_REJECT (MAX_RULES+10)
#define STAT_REPLY_LIMIT (MAX_RULES+11)
#define STAT_BUSY (MAX_RULES+12)
#define STAT_FASTOPEN (MAX_RULES+13)
struct rule {
 u8 action,direction,family,proto;
 u8 src_bits,dst_bits,log,pad;
 u16 sport_lo,sport_hi,dport_lo,dport_hi;
 u32 rate,burst;
 u8 src[16],dst[16],iif[16],oif[16];
 u32 index,reserved;
};
struct header {u32 count,blocks,defaults[3],logging,generation,ready,schema;};
union entry {struct header header;struct rule rule;};
_Static_assert(sizeof(struct rule)==RULE_SIZE,"policy ABI");
struct policy_map {__uint(type,2);__uint(max_entries,MAX_RULES+1);__type(key,u32);__type(value,union entry);};
struct policy_map policy_template SEC(".maps");
struct {__uint(type,12);__uint(max_entries,1);__type(key,u32);__array(values,struct policy_map);} active SEC(".maps")={.values={[0]=&policy_template}};
struct counter {u64 packets;u32 generation,pad;};
MAP(stats,6,u32,struct counter,MAX_RULES+16);
MAP(log_clock,6,u32,struct counter,MAX_RULES+16);
struct reply_tokens {u64 last;u32 tokens,pad;};
MAP(reply_clock,6,u32,struct reply_tokens,1);
struct {__uint(type,27);__uint(max_entries,1048576);} events SEC(".maps");
struct packet {
 u8 src[16],dst[16],iif[16],oif[16];
 u32 len,l4,payload,seq,ack;
 u16 sport,dport,window;
 u8 family,proto,direction,flags,icmp_type,icmp_code,hoplimit,wscale;
};
struct flow_key {u8 a[16],b[16];u16 ap,bp;u8 family,proto;u16 pad;};
struct flow {
 struct bpf_spin_lock lock;
 u32 state;
 u64 last;
 u32 end[2],acked[2],window[2];
 u8 original,scale[2],fin;
 u32 generation;
};
MAP(flows,1,struct flow_key,struct flow,65536);
struct rate_key {u8 src[16];u32 index;u8 family;u8 pad[3];u32 generation;};
struct rate_value {struct bpf_spin_lock lock;u32 pad;u64 last,credit;};
MAP(rates,1,struct rate_key,struct rate_value,16384);
struct event {
 u64 time;
 u32 rule,generation,length,captured;
 u8 family,proto,action,direction;
 u16 sport,dport;
 u8 src[16],dst[16],iif[16],oif[16];
 u8 packet[1280];
};
struct pending_reject {u64 time;u32 seq,ack;u8 original,flags;u8 pad[6];};
MAP(reject_wait,9,struct flow_key,struct pending_reject,16384);
struct scratch {struct packet p,quoted;struct flow_key key,quote_key;u32 busy;};
MAP(work,6,u32,struct scratch,1);
INLINE u16 be16(const u8 *p){return ((u16)p[0]<<8)|p[1];}
INLINE u32 be32(const u8 *p){return ((u32)p[0]<<24)|((u32)p[1]<<16)|((u32)p[2]<<8)|p[3];}
INLINE void count(u32 index,u32 generation){struct counter *n=map_lookup(&stats,&index);if(n){if(n->generation!=generation){n->generation=generation;n->packets=0;}n->packets++;}}
INLINE int finish(int action,u32 generation){count(action==ALLOW?STAT_PASS:STAT_DROP,generation);if(action==REJECT)count(STAT_REJECT,generation);return action==ALLOW?1:0;}
INLINE int addr_equal(const u8 *a,const u8 *b){
#pragma unroll
 for(int i=0;i<16;i++)if(a[i]!=b[i])return 0;
 return 1;
}
INLINE int prefix(const u8 *a,const u8 *b,u8 bits){
#pragma unroll
 for(int i=0;i<16;i++){if(bits>i*8){u32 n=bits-i*8;u8 mask=n>=8?255:(u8)(255<<(8-n));if((a[i]&mask)!=(b[i]&mask))return 0;}}
 return 1;
}
INLINE int name_equal(const u8 *a,const u8 *b){
#pragma unroll
 for(int i=0;i<16;i++){if(a[i]!=b[i])return 0;if(!a[i])return 1;}
 return 1;
}

struct cursor {u32 at,offset,length,error,opt,tcp_length;};
MAP(cursors,6,u32,struct cursor,1);
struct extension_walk {struct bpf_dynptr *ptr;struct packet *p;struct cursor *c;};
static long extension_step(u32 i,void *opaque){
 struct extension_walk *w=opaque;struct cursor *c=w->c;u8 h[8]={};u8 proto=w->p->proto;
 if(proto!=0&&proto!=43&&proto!=44&&proto!=51&&proto!=60&&proto!=135)return 1;
 u32 at=c->at,offset=c->offset,length=c->length;
 if(at>1048576||at<offset||dyn_read(h,8,w->ptr,at,0)){c->error=1;return 1;}
 u32 n;
 if(proto==44){if(be16(h+2)&0xfff9){c->error=1;return 1;}n=8;}
 else if(proto==51)n=((u32)h[1]+2)*4;
 else n=((u32)h[1]+1)*8;
 if(n<8||(u64)at-offset+n>length){c->error=1;return 1;}
 w->p->proto=h[0];c->at=at+n;return 0;
}
struct option_walk {struct bpf_dynptr *ptr;struct packet *p;struct cursor *c;};
static long option_step(u32 i,void *opaque){
 struct option_walk *w=opaque;struct cursor *c=w->c;u8 h[3]={};u32 opt=c->opt,at=c->at,len=c->tcp_length;
 if(opt>=len)return 1;
 if(opt>60||at>1048576||dyn_read(h,1,w->ptr,at+opt,0)){c->error=1;return 1;}
 if(h[0]==0)return 1;if(h[0]==1){c->opt=opt+1;return 0;}
 if(dyn_read(h,2,w->ptr,at+opt,0)){c->error=1;return 1;}
 u8 n=h[1];if(n<2||opt+n>len){c->error=1;return 1;}
 if(h[0]==3&&n==3){if(dyn_read(h,3,w->ptr,at+opt,0)){c->error=1;return 1;}w->p->wscale=h[2]>14?14:h[2];}
 c->opt=opt+n;return 0;
}

/* Parse an IP packet from an skb dynptr. offset is used for ICMP quotations.
 * quoted mode accepts truncated payloads, but never reads beyond the dynptr. */
static __attribute__((noinline)) int parse(struct bpf_dynptr *ptr,struct packet *p,u32 offset,u32 available,int quoted){
 u32 zero=0;struct cursor *cursor=map_lookup(&cursors,&zero);if(!cursor)return -1;__builtin_memset(cursor,0,sizeof(*cursor));
 u8 h[64]={};
 if(dyn_read(h,1,ptr,offset,0))return -1;
 p->family=h[0]>>4;
 u32 at=offset,length=0;
 if(p->family==4){
  if(dyn_read(h,20,ptr,at,0))return -1;
  u32 ihl=(h[0]&15)*4;length=be16(h+2);
  if(ihl<20||length<ihl||(!quoted&&length>available))return -1;
  if(be16(h+6)&0x3fff)return -1;
  __builtin_memcpy(p->src,h+12,4);__builtin_memcpy(p->dst,h+16,4);
  p->proto=h[9];p->hoplimit=h[8];at+=ihl;
 }else if(p->family==6){
  if(dyn_read(h,40,ptr,at,0))return -1;
  length=40+be16(h+4);if(length==40&&available>65535)length=available;
  if(!quoted&&length>available)return -1;
  __builtin_memcpy(p->src,h+8,16);__builtin_memcpy(p->dst,h+24,16);
  p->proto=h[6];p->hoplimit=h[7];at+=40;
  cursor->at=at;cursor->offset=offset;cursor->length=length;
  struct extension_walk ext={.ptr=ptr,.p=p,.c=cursor};
  bpf_loop(32,extension_step,&ext,0);if(cursor->error)return -1;at=cursor->at;
  if(p->proto==0||p->proto==43||p->proto==44||p->proto==51||p->proto==60||p->proto==135)return -1;
 }else return -1;
 if(at-offset>length)return -1;
 p->len=length;p->l4=at;p->payload=length-(at-offset);
 if(p->proto==6||p->proto==17||p->proto==132){
  if(dyn_read(h,8,ptr,at,0))return -1;
  p->sport=be16(h);p->dport=be16(h+2);
  if(quoted)return 0;
  if(p->proto==6){
   if(p->payload<20||dyn_read(h,20,ptr,at,0))return -1;
   u32 tcp_len=(h[12]>>4)*4;if(tcp_len<20||tcp_len>p->payload)return -1;
   p->seq=be32(h+4);p->ack=be32(h+8);p->flags=h[13];if(((p->flags&2)&&(p->flags&5))||((p->flags&1)&&(p->flags&4)))return -1;p->window=be16(h+14);p->payload-=tcp_len;
   if((p->flags&2)&&tcp_len>20){
    cursor->at=at;cursor->opt=20;cursor->tcp_length=tcp_len;
    struct option_walk opt={.ptr=ptr,.p=p,.c=cursor};
    bpf_loop(40,option_step,&opt,0);if(cursor->error)return -1;
   }
  }else if(p->proto==17){
   u32 n=be16(h+4);if(p->payload<8||n>p->payload||(n<8&&!(n==0&&p->family==6&&length>65535)))return -1;
  }else if(p->payload<12)return -1;
 }else if(p->proto==1||p->proto==58){
  if(p->payload<8||dyn_read(h,8,ptr,at,0))return -1;
  if((p->proto==1&&p->family!=4)||(p->proto==58&&p->family!=6))return -1;
  p->icmp_type=h[0];p->icmp_code=h[1];
  if((p->proto==1&&(h[0]==8||h[0]==0))||(p->proto==58&&(h[0]==128||h[0]==129))){p->sport=be16(h+4);p->dport=p->sport;}
 }
 return 0;
}

INLINE int key_for(struct packet *p,struct flow_key *k){
 int reverse=0,decided=0;
#pragma unroll
 for(int i=0;i<16;i++){if(!decided&&p->src[i]!=p->dst[i]){reverse=p->src[i]>p->dst[i];decided=1;}}
 if(!decided)reverse=p->sport>p->dport;
 if(reverse){__builtin_memcpy(k->a,p->dst,16);__builtin_memcpy(k->b,p->src,16);k->ap=p->dport;k->bp=p->sport;}
 else{__builtin_memcpy(k->a,p->src,16);__builtin_memcpy(k->b,p->dst,16);k->ap=p->sport;k->bp=p->dport;}
 k->family=p->family;k->proto=p->proto;return reverse;
}
INLINE u64 expiry(struct flow *f,u8 proto){if(proto==6){if(f->state==4)return 5*NS;if(f->fin)return 30*NS;return f->state==3?432000*NS:60*NS;}return f->state==3?180*NS:30*NS;}

/* Return 1 for a validated existing flow, 0 for a new/expired flow, -1 for
 * an inconsistent TCP packet. No helper calls are made while holding a lock. */
static __attribute__((noinline)) int tracked(struct packet *p,struct flow_key *key,int direction,u64 now){
 struct flow *f=map_lookup(&flows,key);if(!f)return 0;
 int result=1;u8 flags=p->flags;u32 end=p->seq+p->payload+!!(flags&2)+!!(flags&1);
 spin_lock(&f->lock);
 if(now-f->last>expiry(f,p->proto)){result=0;goto out;}
 if(p->proto!=6){
  if((p->proto==1&&p->icmp_type!=0&&p->icmp_type!=8)||(p->proto==58&&p->icmp_type!=128&&p->icmp_type!=129)){result=0;goto out;}
  if(direction!=f->original)f->state=3;
 }else if(f->state==4){result=(flags&2)?0:1;goto out;}
 else if(f->state==1){
  if(direction==f->original){if(!(flags&2)||(flags&16)||p->seq+1!=f->acked[direction])result=-1;}
  else if((flags&0x12)==0x12&&(s32)(p->ack-f->acked[!direction])>=0&&(s32)(p->ack-f->end[!direction])<=0){f->state=2;f->end[direction]=end;f->acked[!direction]=p->ack;f->acked[direction]=p->seq+1;f->scale[direction]=p->wscale;}
  else if((flags&0x14)==0x14&&(s32)(p->ack-f->acked[!direction])>=0&&(s32)(p->ack-f->end[!direction])<=0)f->state=4;
  else result=-1;
 }else if(f->state==2){
  if(direction==f->original&&(flags&16)&&!(flags&2)&&(s32)(p->ack-f->acked[!direction])>=0&&(s32)(p->ack-f->end[!direction])<=0&&(s32)(p->seq-f->acked[direction])>=0&&(s32)(p->seq-f->end[direction])<=0){f->state=3;if((s32)(end-f->end[direction])>0)f->end[direction]=end;f->acked[!direction]=p->ack;}
  else if(direction!=f->original&&(flags&0x12)==0x12&&end==f->end[direction]){}
  else if(direction!=f->original&&(flags&16)&&!(flags&6)&&(s32)(p->seq-f->acked[direction])>=0&&(s32)(p->seq-f->end[direction])<=0&&(s32)(p->ack-f->acked[!direction])>=0&&(s32)(p->ack-f->end[!direction])<=0){if((s32)(end-f->end[direction])>0)f->end[direction]=end;f->acked[!direction]=p->ack;}
  else if(direction==f->original&&(flags&2)&&!(flags&16)&&p->seq+1==f->acked[direction]){}
  else result=-1;
 }else {
  u32 window=f->window[!direction];if(window<65535)window=65535;
  if((flags&2)||(!(flags&16)&&!(flags&4))||(s32)(p->seq-f->end[direction])>(s32)window||(s32)(end-f->acked[direction])<-(s32)window||(flags&16&&(s32)(p->ack-f->end[!direction])>1)){result=-1;goto out;}
  if((s32)(end-f->end[direction])>0)f->end[direction]=end;
  if((flags&16)&&(s32)(p->ack-f->acked[!direction])>0)f->acked[!direction]=p->ack;
  if(flags&1)f->fin|=1<<direction;if(flags&4)f->state=4;
 }
 if(result==1){f->last=now;u32 window=(u32)p->window<<f->scale[direction];if(window>f->window[direction])f->window[direction]=window;}
 out:spin_unlock(&f->lock);return result;
}
static __attribute__((noinline)) int remember(struct packet *p,struct flow_key *key,int direction,u64 now,u32 generation){
 if(p->proto==1&&p->icmp_type!=8)return 0;if(p->proto==58&&p->icmp_type!=128)return 0;
 struct flow f={.last=now,.original=direction,.generation=generation};
 if(p->proto==6){
  u32 end,acked,other;u8 scale=0;
  if((p->flags&4)||(p->flags&1))return 0;
  if((p->flags&2)&&!(p->flags&16)){f.state=1;end=p->seq+p->payload+1;acked=p->seq+1;other=0;scale=p->wscale;}
  else if((p->flags&16)&&!(p->flags&2)){f.state=3;end=p->seq+p->payload;acked=p->seq;other=p->ack;}
  else return -1;
  /* Fixed offsets keep older LLVM from lowering a stack-array index to a
   * bitwise OR on the frame pointer, which the BPF verifier prohibits. */
  f.end[0]=direction?other:end;f.end[1]=direction?end:other;
  f.acked[0]=direction?other:acked;f.acked[1]=direction?acked:other;
  f.scale[0]=direction?0:scale;f.scale[1]=direction?scale:0;
  f.window[0]=direction?65535:p->window;f.window[1]=direction?p->window:65535;
 }else f.state=1;
 return map_update(&flows,key,&f,0);
}

INLINE int matches(struct rule *r,struct packet *p){
 if(r->direction&&r->direction!=p->direction)return 0;
 if(r->family&&r->family!=p->family)return 0;if(r->proto&&r->proto!=p->proto)return 0;
 if(r->sport_lo&&(p->sport<r->sport_lo||p->sport>r->sport_hi))return 0;
 if(r->dport_lo&&(p->dport<r->dport_lo||p->dport>r->dport_hi))return 0;
 if(r->iif[0]&&!name_equal(r->iif,p->iif))return 0;if(r->oif[0]&&!name_equal(r->oif,p->oif))return 0;
 return prefix(r->src,p->src,r->src_bits)&&prefix(r->dst,p->dst,r->dst_bits);
}
struct search {void *policy;struct packet *p;u32 start,count,found,action,index,log,rate,burst,generation;};
static long search_rule(u32 i,void *data){
 struct search *s=data;if(i>=s->count)return 1;
 u32 n=i+s->start;if(n>MAX_RULES)return 1;
 struct rule *r=map_lookup(s->policy,&n);
 if(r&&matches(r,s->p)){s->found=1;s->action=r->action;s->index=r->index;s->log=r->log;s->rate=r->rate;s->burst=r->burst;return 1;}
 return 0;
}
static __attribute__((noinline)) int rate_allowed(struct packet *p,struct search *s,u64 now){
 struct rate_key key={.index=s->index,.family=p->family,.generation=s->generation};__builtin_memcpy(key.src,p->src,16);
 u64 interval=60*NS/(s->rate?s->rate:12);u64 cap=(s->burst?s->burst:6)*interval;
 struct rate_value *v=map_lookup(&rates,&key);
 if(!v){struct rate_value initial={.last=now,.credit=cap};map_update(&rates,&key,&initial,1);v=map_lookup(&rates,&key);if(!v)return 0;}
 int allowed=0;spin_lock(&v->lock);
 u64 elapsed=now-v->last;if(elapsed>=cap||v->credit>=cap-elapsed)v->credit=cap;else v->credit+=elapsed;
 v->last=now;if(v->credit>=interval){v->credit-=interval;allowed=1;}
 spin_unlock(&v->lock);return allowed;
}
static __attribute__((noinline)) void emit(struct bpf_dynptr *ptr,struct packet *p,struct search *s,u32 generation,u64 now){
 int want_log=s->log,want_reply=s->action==REJECT;
 if(want_log){struct counter *gate=map_lookup(&log_clock,&s->index);if(gate){if(gate->generation==generation&&now-gate->packets<200000000ULL)want_log=0;else{gate->generation=generation;gate->packets=now;}}}
 if(want_reply){u32 zero=0;struct reply_tokens *b=map_lookup(&reply_clock,&zero);if(!b)want_reply=0;else{if(!b->last){b->last=now;b->tokens=100;}u64 delta=now-b->last;u64 refill=delta/20000000ULL;if(refill){u64 n=b->tokens+refill;b->tokens=n>100?100:n;b->last=now-delta%20000000ULL;}if(b->tokens)b->tokens--;else want_reply=0;}if(!want_reply)count(STAT_REPLY_LIMIT,generation);}
 if(!want_log&&!want_reply)return;
 struct event *e=ring_reserve(&events,sizeof(struct event),0);if(!e){count(STAT_EVENT_LOST,generation);return;}
 __builtin_memset(e,0,__builtin_offsetof(struct event,packet));
 volatile u64 *clear=(volatile u64 *)e->packet;
#pragma unroll
 for(int i=0;i<160;i++)clear[i]=0;
 e->time=now;e->rule=s->index;e->generation=generation;e->length=p->len;e->family=p->family;e->proto=p->proto;e->action=s->action|(want_log?128:0)|(want_reply?0:64);e->direction=p->direction;e->sport=p->sport;e->dport=p->dport;
 __builtin_memcpy(e->src,p->src,16);__builtin_memcpy(e->dst,p->dst,16);__builtin_memcpy(e->iif,p->iif,16);__builtin_memcpy(e->oif,p->oif,16);
 u32 n=p->len>1280?1280:p->len;if(!dyn_read(e->packet,n,ptr,0,0))e->captured=n;
 ring_submit(e,0);
}
static __attribute__((noinline)) int related(struct bpf_dynptr *ptr,struct scratch *w,u64 now){
 struct packet *p=&w->p;
 if(!((p->proto==1&&(p->icmp_type==3||p->icmp_type==11||p->icmp_type==12))||(p->proto==58&&p->icmp_type>=1&&p->icmp_type<=4)))return 0;
 __builtin_memset(&w->quoted,0,sizeof(w->quoted));__builtin_memset(&w->quote_key,0,sizeof(w->quote_key));
 if(parse(ptr,&w->quoted,p->l4+8,p->payload-8,1))return 0;
 if(!addr_equal(p->dst,w->quoted.src))return 0;
 int quoted_direction=key_for(&w->quoted,&w->quote_key);
 struct pending_reject *r=map_lookup(&reject_wait,&w->quote_key);if(r&&now-r->time<=2*NS&&r->original==quoted_direction)return 1;
 struct flow *f=map_lookup(&flows,&w->quote_key);if(!f)return 0;
 int ok=0;spin_lock(&f->lock);ok=now-f->last<=expiry(f,w->quoted.proto);spin_unlock(&f->lock);return ok;
}
INLINE int reject_response(struct packet *p,struct flow_key *key,int direction,u64 now){
 if(p->proto!=6||!(p->flags&4)||p->payload)return 0;
 struct pending_reject *r=map_lookup(&reject_wait,key);if(!r||now-r->time>2*NS||direction==r->original)return 0;
 return p->flags==r->flags&&p->seq==r->seq&&(!(r->flags&16)||p->ack==r->ack);
}
INLINE void remember_reject(struct packet *p,struct flow_key *key,int direction,u64 now){
 struct pending_reject r={.time=now,.original=direction};
 if(p->proto==6){if(p->flags&4)return;if(p->flags&16){r.seq=p->ack;r.flags=4;}else{r.ack=p->seq+p->payload+!!(p->flags&2)+!!(p->flags&1);r.flags=0x14;}}
 map_update(&reject_wait,key,&r,0);
}
INLINE int essential(struct packet *p){
 if((p->iif[0]=='l'&&p->iif[1]=='o'&&!p->iif[2])||(p->oif[0]=='l'&&p->oif[1]=='o'&&!p->oif[2]))return 1;
 if(p->proto==58&&p->icmp_code==0&&p->icmp_type>=133&&p->icmp_type<=136&&p->hoplimit==255&&p->direction!=ROUTE)return 1;
 if(p->direction==IN&&p->proto==17&&((p->family==4&&p->sport==67&&p->dport==68)||(p->family==6&&p->sport==547&&p->dport==546)))return 1;
 return 0;
}
static __attribute__((noinline)) int enforce(struct bpf_nf_ctx *ctx,struct scratch *w){
 u32 z=0;struct packet *p=&w->p;
 const struct nf_hook_state *state=ctx->state;
 p->direction=state->hook==1?IN:(state->hook==3?OUT:ROUTE);
 if(state->in)__builtin_memcpy(p->iif,state->in->name,16);
 if(state->out)__builtin_memcpy(p->oif,state->out->name,16);
 struct bpf_dynptr ptr;if(bpf_dynptr_from_skb((struct __sk_buff *)ctx->skb,0,&ptr))return 0;
 void *policy=map_lookup(&active,&z);if(!policy)return 0;
 struct header *h=map_lookup(policy,&z);if(!h||!h->ready||h->schema!=2||h->count>MAX_RULES||h->blocks>h->count)return 0;
 u32 generation=h->generation,logging=h->logging;
 if(parse(&ptr,p,0,ctx->skb->len,0)){count(STAT_INVALID,generation);return finish(DENY,generation);}
 if(p->proto==6&&(p->flags&2)&&p->payload)count(STAT_FASTOPEN,generation);
 u32 dir=p->direction;if(dir<1||dir>3)return 0;
 u32 action=h->defaults[dir-1];u64 now=ktime_ns();
 struct search s={.policy=policy,.p=p,.start=1,.count=h->blocks,.generation=generation};
 bpf_loop(s.count,search_rule,&s,0);
 if(s.found){count(s.index,generation);if(logging){s.log=1;s.action=DENY;emit(&ptr,p,&s,generation,now);}return finish(DENY,generation);}
 int direction=key_for(p,&w->key);
 if(reject_response(p,&w->key,direction,now))return finish(ALLOW,generation);
 int ct=tracked(p,&w->key,direction,now);
 if(ct<0){count(STAT_INVALID,generation);return finish(DENY,generation);}
 if(ct||related(&ptr,w,now)){count(STAT_STATE,generation);return finish(ALLOW,generation);}
 s.start=h->blocks+1;s.count=h->count-h->blocks;
 bpf_loop(s.count,search_rule,&s,0);
 u32 index=STAT_DEFAULT+p->direction-1;
 if(s.found){action=s.action;index=s.index;}
 else if(essential(p))action=ALLOW;
 if(action==LIMIT){if(rate_allowed(p,&s,now))action=ALLOW;else{action=DENY;count(STAT_RATE,generation);}}
 if(action==ALLOW&&remember(p,&w->key,direction,now,generation)){count(STAT_CT_FULL,generation);action=DENY;}
 count(index,generation);
 if(action==REJECT)remember_reject(p,&w->key,direction,now);
 if(action==REJECT||s.log||(logging&&action!=ALLOW)){s.index=index;s.action=action;s.log=s.log||(logging&&action!=ALLOW);emit(&ptr,p,&s,generation,now);}
 int verdict=finish(action,generation);
 /* A bounded userspace event consumer emits TCP/ICMP reject responses. */

 return verdict;
}
SEC("netfilter") int ebpfw_full(struct bpf_nf_ctx *ctx){
 u32 zero=0;struct scratch *w=map_lookup(&work,&zero);if(!w)return 0;
 if(__sync_val_compare_and_swap(&w->busy,0,1)){void *inner=map_lookup(&active,&zero);if(inner){struct header *h=map_lookup(inner,&zero);if(h){count(STAT_BUSY,h->generation);count(STAT_DROP,h->generation);}}return 0;}
 __builtin_memset(w,0,__builtin_offsetof(struct scratch,busy));
 int result=enforce(ctx,w);__sync_val_compare_and_swap(&w->busy,1,0);return result;
}
/* Optional pre-stack acceleration only for explicit absolute source blocks.
 * Every other packet is delegated to the authoritative eBPF Netfilter policy. */
struct lpm_key {u32 prefix_len;u8 address[16];};
struct {__uint(type,11);__uint(max_entries,MAX_RULES);__uint(map_flags,1);__type(key,struct lpm_key);__type(value,u32);} early4 SEC(".maps");
struct {__uint(type,11);__uint(max_entries,MAX_RULES);__uint(map_flags,1);__type(key,struct lpm_key);__type(value,u32);} early6 SEC(".maps");
MAP(early_enabled,2,u32,u32,1);
struct xdp_md {u32 data,data_end,data_meta,ingress_ifindex,rx_queue_index,egress_ifindex;};
SEC("xdp.frags") int ebpfw_early(struct xdp_md *ctx){
 u32 z=0;u32 *enabled=map_lookup(&early_enabled,&z);if(!enabled||!*enabled)return 2;
 const u8 *data=(void *)(unsigned long)ctx->data,*end=(void *)(unsigned long)ctx->data_end;
 if(data+14>end)return 2;u32 off=14;u16 ether=be16(data+12);
#pragma unroll
 for(int i=0;i<2;i++){if(ether==0x8100||ether==0x88a8){if(data+off+4>end)return 2;ether=be16(data+off+2);off+=4;}}
 struct lpm_key key={};u32 *index=0;
 if(ether==0x0800){if(data+off+20>end||(data[off]>>4)!=4)return 2;key.prefix_len=32;__builtin_memcpy(key.address,data+off+12,4);index=map_lookup(&early4,&key);}
 else if(ether==0x86dd){if(data+off+40>end||(data[off]>>4)!=6)return 2;key.prefix_len=128;__builtin_memcpy(key.address,data+off+8,16);index=map_lookup(&early6,&key);}
 if(!index)return 2;void *policy=map_lookup(&active,&z);if(!policy)return 2;struct header *h=map_lookup(policy,&z);if(!h||!h->ready)return 2;
 count(*index,h->generation);count(STAT_DROP,h->generation);return 1;
}
char LICENSE[] SEC("license")="GPL";
