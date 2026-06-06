// SPDX-License-Identifier: GPL-2.0
/*
 * diag rule engine implementation.
 *
 * Per device (bus,dev,vid,pid) we keep a bounded, time-evicted ring of recent
 * normalized events. When a trigger event arrives we look back over that window
 * to evaluate event-driven rules; deadline rules are checked on a periodic tick.
 * Findings (conclusion + evidence chain) are printed live and tallied for a
 * summary at exit. Memory is bounded (fixed device and per-device caps).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "usbtrace/cli.h"
#include "usbtrace/log.h"
#include "engine.h"

#define WIN_MAX_DEVS	128
/*
 * Per-device lookback ring. It must hold at least within_ms x peak event rate so
 * a rule's lookback isn't truncated. isoc streams are the stress case: a uvc/uac
 * device emits a per-URB class record (~250/s) interleaved with low-rate
 * semantic records (uvc frames ~15/s); a small ring lets the URB flood evict the
 * frame events before a frame rule (e.g. 3s lookback) can accumulate them. 1024
 * covers a ~3s lookback at ~300 events/s. (128 devs x 1024 ~= 14 MB.)
 */
#define WIN_MAX_EVENTS	1024
#define RETENTION_NS	(10ULL * 1000000000ULL)	/* drop idle devices after 10s */
#define COOLDOWN_NS	(2ULL * 1000000000ULL)	/* per (device,rule) anti-spam */
#define MAX_EVIDENCE	6

struct devwin {
	int used;
	struct diag_devkey key;
	uint16_t vid;			/* learned (last non-zero) for display */
	uint16_t pid;
	uint64_t last_seen_ns;

	struct diag_event ev[WIN_MAX_EVENTS];
	int head;	/* next write slot */
	int count;	/* valid entries (<= WIN_MAX_EVENTS) */

	uint16_t seen_states;		/* bit per enum usb_device_state */
	uint64_t state_ts[9];		/* first-seen ts per state */

	uint64_t last_fire_ns[DIAG_MAX_RULES];	/* event-rule cooldown */
	uint8_t dl_fired[DIAG_MAX_RULES];	/* deadline-rule latch */
};

struct diag_engine {
	struct diag_rule *rules;
	int nrules;

	struct devwin devs[WIN_MAX_DEVS];

	/* summary */
	unsigned long fire_count[DIAG_MAX_RULES];
	unsigned long total_fired;
};

static const char *sev_str(enum diag_severity s)
{
	switch (s) {
	case SEV_ERROR: return "error";
	case SEV_WARN:  return "warn";
	default:        return "info";
	}
}

static const char *vb2_op_label(uint8_t op)
{
	switch (op) {
	case 1:  return "queue";
	case 2:  return "qbuf";
	case 3:  return "dqbuf";
	case 4:  return "STARVE";
	default: return "done";
	}
}

static const char *kind_str(uint32_t k)
{
	switch (k) {
	case 1: return "urb";
	case 2: return "enum";
	case 3: return "power";
	case 4: return "lifecycle";
	case 5: return "class";
	case 6: return "uvc_frame";
	case 7: return "uvc_vb2";
	default: return "?";
	}
}

uint64_t diag_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static long ev_field_val(const struct diag_event *e, enum diag_field f)
{
	switch (f) {
	case F_KIND:       return e->kind;
	case F_IS_SUBMIT:  return e->is_submit;
	case F_STATUS:     return e->status;
	case F_XFER_TYPE:  return e->xfer_type;
	case F_DIR_IN:     return e->dir_in;
	case F_EP:         return e->ep;
	case F_ACTION:     return e->action;
	case F_OLD_STATE:  return e->old_state;
	case F_NEW_STATE:  return e->new_state;
	case F_LATENCY_NS: return e->latency_ns;
	case F_ACTUAL:     return e->actual;
	case F_LENGTH:     return e->length;
	case F_ERROR_COUNT: return e->error_count;
	case F_CLASS:      return e->cls;
	case F_FRAME_BYTES:    return e->frame_bytes;
	case F_FRAME_INTERVAL: return e->frame_interval_ns;
	case F_FRAME_ERRORED:  return e->frame_errored;
	case F_VB2_SEQUENCE:   return e->vb2_sequence;
	case F_VB2_SEQ_GAP:    return e->vb2_seq_gap;
	case F_VB2_BYTESUSED: return e->vb2_bytesused;
	case F_VB2_INTERVAL:   return e->vb2_interval_ns;
	case F_WIRE_TO_VB2_NS: return e->wire_to_vb2_ns;
	case F_VB2_OP:         return e->vb2_op;
	case F_VB2_STARVED:    return e->vb2_starved;
	case F_VB2_NUM_BUFFERS: return e->vb2_num_buffers;
	case F_VB2_QUEUED:     return e->vb2_queued;
	case F_VB2_DRV_OWNED:  return e->vb2_drv_owned;
	default:           return 0;
	}
}

static int match_one(const struct diag_match *m, long v)
{
	switch (m->op) {
	case OP_NE:  return v != m->value;
	case OP_GTE: return v >= m->value;
	case OP_LTE: return v <= m->value;
	case OP_EQ:
	default:     return v == m->value;
	}
}

static int match_fields(const struct diag_cond *c, const struct diag_event *e)
{
	int i;

	for (i = 0; i < c->nmatch; i++) {
		long v = ev_field_val(e, c->match[i].field);

		if (!match_one(&c->match[i], v))
			return 0;
	}
	return 1;
}

static int status_ok(const struct diag_cond *c, const struct diag_event *e)
{
	int i;

	if (c->nstatus == 0)
		return 1;
	for (i = 0; i < c->nstatus; i++) {
		if (e->status == c->status_in[i])
			return 1;
	}
	return 0;
}

/* Does an event satisfy a (lookback) condition's per-event predicate? */
static int cond_event_pred(const struct diag_cond *c, const struct diag_event *e)
{
	if (c->has_kind && e->kind != c->kind)
		return 0;
	if (!match_fields(c, e))
		return 0;
	if (!status_ok(c, e))
		return 0;
	return 1;
}

/* Trigger match: kind + match equality only. */
static int trigger_match(const struct diag_cond *c, const struct diag_event *e)
{
	if (c->has_kind && e->kind != c->kind)
		return 0;
	return match_fields(c, e);
}

/* ---- device window ------------------------------------------------------- */

static int key_eq(const struct diag_devkey *a, const struct diag_devkey *b)
{
	return a->busnum == b->busnum && a->devnum == b->devnum;
}

static struct devwin *win_get(struct diag_engine *e, const struct diag_devkey *k,
			      int create)
{
	struct devwin *lru = NULL;
	int i;

	for (i = 0; i < WIN_MAX_DEVS; i++) {
		if (e->devs[i].used && key_eq(&e->devs[i].key, k))
			return &e->devs[i];
	}
	if (!create)
		return NULL;

	for (i = 0; i < WIN_MAX_DEVS; i++) {
		if (!e->devs[i].used) {
			memset(&e->devs[i], 0, sizeof(e->devs[i]));
			e->devs[i].used = 1;
			e->devs[i].key = *k;
			return &e->devs[i];
		}
		if (!lru || e->devs[i].last_seen_ns < lru->last_seen_ns)
			lru = &e->devs[i];
	}
	/* full: recycle the least-recently-seen device */
	memset(lru, 0, sizeof(*lru));
	lru->used = 1;
	lru->key = *k;
	return lru;
}

static void win_push(struct devwin *w, const struct diag_event *ev)
{
	w->ev[w->head] = *ev;
	w->head = (w->head + 1) % WIN_MAX_EVENTS;
	if (w->count < WIN_MAX_EVENTS)
		w->count++;
}

/* Iterate window events newest-first; idx 0..count-1. */
static const struct diag_event *win_at(const struct devwin *w, int idx)
{
	int pos = (w->head - 1 - idx + 2 * WIN_MAX_EVENTS) % WIN_MAX_EVENTS;

	return &w->ev[pos];
}

/* ---- finding output ------------------------------------------------------ */

/* Expand {vid}{pid}{bus}{dev}{count}{window}{comm} in a template. */
static void expand(const char *tmpl, const struct devwin *w, long count,
		   long window_ms, const char *comm, char *out, size_t outsz)
{
	size_t o = 0;
	const char *p = tmpl ? tmpl : "";

	while (*p && o + 1 < outsz) {
		if (*p == '{') {
			const char *e = strchr(p, '}');
			char key[16];
			char val[64];

			if (e && (size_t)(e - p - 1) < sizeof(key)) {
				size_t kl = (size_t)(e - p - 1);

				memcpy(key, p + 1, kl);
				key[kl] = '\0';
				val[0] = '\0';
				if (!strcmp(key, "vid"))
					snprintf(val, sizeof(val), "%04x",
						 w->vid);
				else if (!strcmp(key, "pid"))
					snprintf(val, sizeof(val), "%04x",
						 w->pid);
				else if (!strcmp(key, "bus"))
					snprintf(val, sizeof(val), "%u",
						 w->key.busnum);
				else if (!strcmp(key, "dev"))
					snprintf(val, sizeof(val), "%u",
						 w->key.devnum);
				else if (!strcmp(key, "count"))
					snprintf(val, sizeof(val), "%ld",
						 count);
				else if (!strcmp(key, "window"))
					snprintf(val, sizeof(val), "%ld",
						 window_ms);
				else if (!strcmp(key, "comm"))
					snprintf(val, sizeof(val), "%s",
						 comm ? comm : "");
				else
					snprintf(val, sizeof(val), "{%s}", key);

				o += (size_t)snprintf(out + o, outsz - o, "%s",
						      val);
				p = e + 1;
				continue;
			}
		}
		out[o++] = *p++;
	}
	out[o < outsz ? o : outsz - 1] = '\0';
}

struct evidence {
	const struct diag_event *ev[MAX_EVIDENCE];
	int n;
};

static void print_finding(struct diag_engine *e, const struct diag_rule *r,
			  const struct devwin *w, uint64_t ref_ns, long count,
			  long window_ms, const char *comm,
			  const struct evidence *ev)
{
	char concl[512];
	char fix[512];
	int i;

	expand(r->conclusion, w, count, window_ms, comm, concl, sizeof(concl));
	expand(r->fix, w, count, window_ms, comm, fix, sizeof(fix));

	if (usbtrace_json) {
		char esc[1024];

		printf("{\"event\":\"diag\",\"severity\":\"%s\",\"rule\":\"%s\",",
		       sev_str(r->severity), r->id);
		printf("\"vid\":\"0x%04x\",\"pid\":\"0x%04x\",\"bus\":%u,\"dev\":%u,",
		       w->vid, w->pid, w->key.busnum, w->key.devnum);
		printf("\"count\":%ld,\"conclusion\":\"%s\",",
		       count, usbtrace_json_escape(concl, esc, sizeof(esc)));
		printf("\"fix\":\"%s\",\"evidence\":[",
		       usbtrace_json_escape(fix, esc, sizeof(esc)));
		for (i = 0; ev && i < ev->n; i++) {
			const struct diag_event *x = ev->ev[i];
			double dt = (double)(ref_ns - x->ts_ns) / 1e6;

			if (x->kind == USBTRACE_EVT_UVC_FRAME) {
				double fps = x->frame_interval_ns ?
					1e9 / x->frame_interval_ns : 0.0;

				printf("%s{\"dt_ms\":%.1f,\"kind\":\"uvc_frame\","
				       "\"fps\":%.1f,\"interval_ms\":%.1f,"
				       "\"bytes\":%u,\"errored\":%u}",
				       i ? "," : "", dt, fps,
				       x->frame_interval_ns / 1e6,
				       x->frame_bytes, x->frame_errored);
			} else if (x->kind == USBTRACE_EVT_UVC_VB2) {
				double fps = x->vb2_interval_ns ?
					1e9 / x->vb2_interval_ns : 0.0;

				printf("%s{\"dt_ms\":%.1f,\"kind\":\"uvc_vb2\","
				       "\"op\":\"%s\",\"seq\":%u,\"seq_gap\":%u,"
				       "\"starved\":%u,\"pool\":%u,\"queued\":%u,"
				       "\"drv_owned\":%u,"
				       "\"fps\":%.1f,\"interval_ms\":%.1f,"
				       "\"bytes\":%u,\"wire_to_vb2_ms\":%.3f}",
				       i ? "," : "", dt, vb2_op_label(x->vb2_op),
				       x->vb2_sequence, x->vb2_seq_gap,
				       x->vb2_starved, x->vb2_num_buffers,
				       x->vb2_queued, x->vb2_drv_owned,
				       fps, x->vb2_interval_ns / 1e6,
				       x->vb2_bytesused,
				       x->wire_to_vb2_ns / 1e6);
			} else {
				printf("%s{\"dt_ms\":%.1f,\"kind\":\"%s\","
				       "\"status\":%d}",
				       i ? "," : "", dt, kind_str(x->kind),
				       x->status);
			}
		}
		printf("]}\n");
		return;
	}

	printf("\n[DIAG] %-5s %-22s %04x:%04x bus%u-dev%u\n",
	       sev_str(r->severity), r->id, w->vid, w->pid,
	       w->key.busnum, w->key.devnum);
	printf("  conclusion: %s\n", concl);
	if (r->fix && r->fix[0])
		printf("  fix:        %s\n", fix);
	if (ev && ev->n) {
		printf("  evidence:\n");
		for (i = 0; i < ev->n; i++) {
			const struct diag_event *x = ev->ev[i];
			double dt = (double)(ref_ns - x->ts_ns) / 1e9;

			if (x->kind == 1) /* urb */
				printf("    %+8.3fs urb %-8s ep%u %s status=%d\n",
				       -dt, x->is_submit ? "submit" : "complete",
				       x->ep, x->dir_in ? "IN" : "OUT",
				       x->status);
			else if (x->kind == USBTRACE_EVT_UVC_FRAME)
				printf("    %+8.3fs uvc_frame %-4s %5.1ffps "
				       "intv=%5.1fms %uB\n",
				       -dt, x->frame_errored ? "DROP" : "ok",
				       x->frame_interval_ns ?
					       1e9 / x->frame_interval_ns : 0.0,
				       x->frame_interval_ns / 1e6,
				       x->frame_bytes);
			else if (x->kind == USBTRACE_EVT_UVC_VB2) {
				double fps = x->vb2_interval_ns ?
					1e9 / x->vb2_interval_ns : 0.0;
				const char *tag = vb2_op_label(x->vb2_op);

				if (x->vb2_starved || x->vb2_op == 4)
					printf("    %+8.3fs uvc_vb2 %-6s pool=%u "
					       "q=%u drv=%u\n",
					       -dt, tag, x->vb2_num_buffers,
					       x->vb2_queued, x->vb2_drv_owned);
				else if (x->vb2_op && x->vb2_op != 4)
					printf("    %+8.3fs uvc_vb2 %-6s pool=%u "
					       "q=%u drv=%u\n",
					       -dt, tag, x->vb2_num_buffers,
					       x->vb2_queued, x->vb2_drv_owned);
				else if (x->wire_to_vb2_ns)
					printf("    %+8.3fs uvc_vb2 %-4s seq=%u "
					       "%5.1ffps intv=%5.1fms %uB "
					       "pool=%u q=%u drv=%u w2v=%.2fms\n",
					       -dt, x->vb2_seq_gap ? "GAP" : "ok",
					       x->vb2_sequence, fps,
					       x->vb2_interval_ns / 1e6,
					       x->vb2_bytesused,
					       x->vb2_num_buffers, x->vb2_queued,
					       x->vb2_drv_owned,
					       x->wire_to_vb2_ns / 1e6);
				else
					printf("    %+8.3fs uvc_vb2 %-4s seq=%u "
					       "%5.1ffps intv=%5.1fms %uB "
					       "pool=%u q=%u drv=%u\n",
					       -dt, x->vb2_seq_gap ? "GAP" : "ok",
					       x->vb2_sequence, fps,
					       x->vb2_interval_ns / 1e6,
					       x->vb2_bytesused,
					       x->vb2_num_buffers, x->vb2_queued,
					       x->vb2_drv_owned);
			}
			else
				printf("    %+8.3fs %s\n", -dt,
				       kind_str(x->kind));
		}
	}
	fflush(stdout);
}

/* ---- evaluation ---------------------------------------------------------- */

/* Evaluate one when condition against the window; returns match count and
 * collects evidence (newest-first). */
static long eval_when(const struct devwin *w, const struct diag_cond *c,
		      uint64_t ref_ns, struct evidence *ev)
{
	long cnt = 0;
	int i;

	for (i = 0; i < w->count; i++) {
		const struct diag_event *x = win_at(w, i);

		if (x->ts_ns > ref_ns)
			continue;
		if (c->has_within_ms &&
		    (ref_ns - x->ts_ns) > (uint64_t)c->within_ms * 1000000ULL)
			continue;
		if (!cond_event_pred(c, x))
			continue;
		if (ev && ev->n < MAX_EVIDENCE)
			ev->ev[ev->n++] = x;
		cnt++;
	}
	return cnt;
}

static int cooldown_ok(struct devwin *w, int ridx, uint64_t now)
{
	if (w->last_fire_ns[ridx] &&
	    now - w->last_fire_ns[ridx] < COOLDOWN_NS)
		return 0;
	w->last_fire_ns[ridx] = now;
	return 1;
}

static void emit(struct diag_engine *e, int ridx, struct devwin *w,
		 uint64_t ref_ns, long count, long window_ms, const char *comm,
		 const struct evidence *ev)
{
	print_finding(e, &e->rules[ridx], w, ref_ns, count, window_ms, comm, ev);
	e->fire_count[ridx]++;
	e->total_fired++;
}

/* Reset per-enumeration state so deadline rules can re-arm on the next bring-up
 * (called on NOTATTACHED transitions and on disconnect). */
static void dev_reset_enum(struct devwin *w)
{
	w->seen_states = 0;
	memset(w->state_ts, 0, sizeof(w->state_ts));
	memset(w->dl_fired, 0, sizeof(w->dl_fired));
}

void diag_engine_ingest(struct diag_engine *e, const struct diag_event *evt)
{
	struct diag_devkey k = diag_event_key(evt);
	struct devwin *w = win_get(e, &k, 1);
	int ri;

	w->last_seen_ns = evt->ts_ns;
	if (evt->vid)
		w->vid = evt->vid;
	if (evt->pid)
		w->pid = evt->pid;
	win_push(w, evt);

	if (evt->kind == 2 /* enum */) {
		if (evt->new_state == 0 /* NOTATTACHED: fresh enumeration */)
			dev_reset_enum(w);
		if (evt->new_state < 9) {
			w->seen_states |= (uint16_t)(1u << evt->new_state);
			if (!w->state_ts[evt->new_state])
				w->state_ts[evt->new_state] = evt->ts_ns;
		}
	} else if (evt->kind == 4 /* lifecycle */ && evt->action == 1 /* disconnect */) {
		dev_reset_enum(w);
	}

	for (ri = 0; ri < e->nrules; ri++) {
		struct diag_rule *r = &e->rules[ri];
		struct evidence ev = { .n = 0 };
		long count = 0, window_ms = 0;
		int j, ok = 1;

		if (r->type != RULE_EVENT)
			continue;
		if (!trigger_match(&r->trigger, evt))
			continue;

		for (j = 0; j < r->nwhen; j++) {
			struct diag_cond *c = &r->when[j];
			long need = c->has_count_gte ? c->count_gte : 1;
			long n = eval_when(w, c, evt->ts_ns, &ev);

			if (n < need) {
				ok = 0;
				break;
			}
			if (n > count)
				count = n;
			if (c->has_within_ms && c->within_ms > window_ms)
				window_ms = c->within_ms;
		}
		if (ok && cooldown_ok(w, ri, diag_now_ns()))
			emit(e, ri, w, evt->ts_ns, count, window_ms, evt->comm,
			     &ev);
	}
}

void diag_engine_tick(struct diag_engine *e, uint64_t now_ns)
{
	int i, ri;

	for (i = 0; i < WIN_MAX_DEVS; i++) {
		struct devwin *w = &e->devs[i];

		if (!w->used)
			continue;

		/* deadline rules */
		for (ri = 0; ri < e->nrules; ri++) {
			struct diag_rule *r = &e->rules[ri];
			uint16_t rb, wb;

			if (r->type != RULE_DEADLINE)
				continue;
			if (r->dl_reached_state < 0 ||
			    r->dl_reached_state > 8)
				continue;
			rb = (uint16_t)(1u << r->dl_reached_state);
			if (!(w->seen_states & rb))
				continue;
			if (r->dl_without_state >= 0 &&
			    r->dl_without_state <= 8) {
				wb = (uint16_t)(1u << r->dl_without_state);
				if (w->seen_states & wb)
					continue;
			}
			if (now_ns - w->state_ts[r->dl_reached_state] <
			    (uint64_t)r->dl_timeout_ms * 1000000ULL)
				continue;
			if (w->dl_fired[ri]) /* latch: report once per episode */
				continue;
			w->dl_fired[ri] = 1;
			emit(e, ri, w, now_ns, 0, r->dl_timeout_ms, NULL, NULL);
		}

		/* evict idle device windows */
		if (now_ns - w->last_seen_ns > RETENTION_NS)
			w->used = 0;
	}
}

void diag_engine_report(struct diag_engine *e)
{
	int i;

	if (usbtrace_json) {
		printf("{\"event\":\"diag_summary\",\"total\":%lu,\"rules\":[",
		       e->total_fired);
		for (i = 0; i < e->nrules; i++)
			printf("%s{\"rule\":\"%s\",\"hits\":%lu}", i ? "," : "",
			       e->rules[i].id, e->fire_count[i]);
		printf("]}\n");
		return;
	}

	fprintf(stderr, "\n--- diag summary ---\n");
	if (!e->total_fired) {
		fprintf(stderr, "no findings.\n");
		return;
	}
	fprintf(stderr, "total findings: %lu\n", e->total_fired);
	for (i = 0; i < e->nrules; i++) {
		if (e->fire_count[i])
			fprintf(stderr, "  %-24s %lu\n", e->rules[i].id,
				e->fire_count[i]);
	}
}

struct diag_engine *diag_engine_create(struct diag_rule *rules, int nrules)
{
	struct diag_engine *e = calloc(1, sizeof(*e));

	if (!e)
		return NULL;
	e->rules = rules;
	e->nrules = nrules;
	return e;
}

void diag_engine_destroy(struct diag_engine *e)
{
	if (!e)
		return;
	diag_rules_free(e->rules, e->nrules);
	free(e);
}

void diag_rules_free(struct diag_rule *rules, int nrules)
{
	int i;

	if (!rules)
		return;
	for (i = 0; i < nrules; i++) {
		free(rules[i].id);
		free(rules[i].name);
		free(rules[i].conclusion);
		free(rules[i].fix);
	}
	free(rules);
}
