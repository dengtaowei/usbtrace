/* SPDX-License-Identifier: GPL-2.0 */
/*
 * diag rule engine: per-device sliding window + rule evaluation.
 *
 * The engine is fed normalized struct diag_event records (see diag.h). For
 * event-driven rules it looks back over the device's recent-event window when a
 * trigger arrives; for deadline rules it checks elapsed time on a periodic tick.
 * Findings are printed live (conclusion + evidence chain) and tallied for an
 * end-of-session summary.
 */
#ifndef __USBTRACE_DIAG_ENGINE_H
#define __USBTRACE_DIAG_ENGINE_H

#include <stdint.h>

#include "diag.h"

#define DIAG_MAX_RULES		64
#define DIAG_MAX_WHEN		8
#define DIAG_MAX_MATCH		8
#define DIAG_MAX_STATUS		16

/* Fields of struct diag_event addressable from the YAML DSL. */
enum diag_field {
	F_NONE = 0,
	F_KIND,
	F_IS_SUBMIT,
	F_STATUS,
	F_XFER_TYPE,
	F_DIR_IN,
	F_EP,
	F_ACTION,
	F_OLD_STATE,
	F_NEW_STATE,
	F_LATENCY_NS,
	F_ACTUAL,
	F_LENGTH,
	F_ERROR_COUNT,
	F_CLASS,
};

enum diag_severity {
	SEV_INFO = 0,
	SEV_WARN,
	SEV_ERROR,
};

/* A single field constraint: field == value, or field != value when neg. */
struct diag_match {
	enum diag_field field;
	long value;
	int neg;	/* 1 = require field != value (DSL "!value") */
};

/* One lookback condition (event-driven rules). */
struct diag_cond {
	int has_kind;
	uint32_t kind;

	struct diag_match match[DIAG_MAX_MATCH];
	int nmatch;

	long status_in[DIAG_MAX_STATUS];
	int nstatus;

	int has_within_ms;
	long within_ms;

	int has_count_gte;
	long count_gte;
};

enum diag_rule_type {
	RULE_EVENT = 0,	  /* trigger + when lookback */
	RULE_DEADLINE,	  /* reached a state but not another within timeout */
};

struct diag_rule {
	char *id;
	char *name;
	char *conclusion;
	char *fix;
	enum diag_severity severity;
	enum diag_rule_type type;

	/* RULE_EVENT */
	struct diag_cond trigger;	/* kind + match only */
	struct diag_cond when[DIAG_MAX_WHEN];
	int nwhen;

	/* RULE_DEADLINE */
	int dl_reached_state;	/* state that starts the clock */
	int dl_without_state;	/* state that, if seen, cancels the alarm */
	long dl_timeout_ms;
};

struct diag_engine;

struct diag_engine *diag_engine_create(struct diag_rule *rules, int nrules);
void diag_engine_destroy(struct diag_engine *e);

/* Ingest one normalized event: append to the device window and evaluate any
 * event-driven rules it triggers (firing findings live). */
void diag_engine_ingest(struct diag_engine *e, const struct diag_event *ev);

/* Periodic maintenance: evaluate deadline rules and evict stale windows. */
void diag_engine_tick(struct diag_engine *e, uint64_t now_ns);

/* Print the end-of-session summary. */
void diag_engine_report(struct diag_engine *e);

/* Monotonic clock matching bpf_ktime_get_ns (CLOCK_MONOTONIC). */
uint64_t diag_now_ns(void);

/* Free a rule array built by the loader (frees owned strings too). */
void diag_rules_free(struct diag_rule *rules, int nrules);

#endif /* __USBTRACE_DIAG_ENGINE_H */
