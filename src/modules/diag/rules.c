// SPDX-License-Identifier: GPL-2.0
/*
 * diag rule loader. Parses the YAML knowledge base into the engine's rule model
 * using libyaml's document API (a simple tree walk).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <yaml.h>

#include "usbtrace/log.h"
#include "rules.h"

/* Default knowledge base, embedded at build time (see Makefile EMBED rule). */
#include "modules/diag/rules_default.h"

struct symbol {
	const char *name;
	long value;
};

/* kind names (enum usbtrace_event_kind). */
static const struct symbol kind_syms[] = {
	{ "urb", 1 }, { "enum", 2 }, { "power", 3 }, { "lifecycle", 4 },
	{ "class", 5 }, { "uvc_frame", 6 }, { "uvc_vb2", 7 },
	{ NULL, 0 },
};

/* action + device-state names, usable as scalar values in the DSL. */
static const struct symbol enum_syms[] = {
	/* lifecycle_action */
	{ "connect", 0 }, { "disconnect", 1 },
	/* power_action */
	{ "autosuspend", 0 }, { "autoresume", 1 },
	/* enum usb_device_state */
	{ "NOTATTACHED", 0 }, { "ATTACHED", 1 }, { "POWERED", 2 },
	{ "RECONNECTING", 3 }, { "UNAUTHED", 4 }, { "DEFAULT", 5 },
	{ "ADDRESS", 6 }, { "CONFIGURED", 7 }, { "SUSPENDED", 8 },
	/* enum usbtrace_class (for `class:` field / value) */
	{ "video", 0 }, { "audio", 1 }, { "hid", 2 }, 	{ "storage", 3 },
	/* enum uvc_vb2_op (for `vb2_op:`) */
	{ "vb2_done", 0 }, { "vb2_queue", 1 }, { "vb2_qbuf", 2 },
	{ "vb2_dqbuf", 3 }, { "vb2_starved", 4 },
	/* enum usbtrace_xfer_type (for `xfer_type:`) */
	{ "isoc", 0 }, { "int", 1 }, { "control", 2 }, { "bulk", 3 },
	{ NULL, 0 },
};

static const struct symbol field_syms[] = {
	{ "kind", F_KIND },
	{ "is_submit", F_IS_SUBMIT },
	{ "status", F_STATUS },
	{ "xfer_type", F_XFER_TYPE },
	{ "dir_in", F_DIR_IN },
	{ "ep", F_EP },
	{ "action", F_ACTION },
	{ "old_state", F_OLD_STATE },
	{ "new_state", F_NEW_STATE },
	{ "latency_ns", F_LATENCY_NS },
	{ "actual", F_ACTUAL },
	{ "length", F_LENGTH },
	{ "error_count", F_ERROR_COUNT },
	{ "class", F_CLASS },
	{ "frame_bytes", F_FRAME_BYTES },
	{ "frame_interval_ns", F_FRAME_INTERVAL },
	{ "frame_errored", F_FRAME_ERRORED },
	{ "vb2_sequence", F_VB2_SEQUENCE },
	{ "vb2_seq_gap", F_VB2_SEQ_GAP },
	{ "vb2_bytesused", F_VB2_BYTESUSED },
	{ "vb2_interval_ns", F_VB2_INTERVAL },
	{ "wire_to_vb2_ns", F_WIRE_TO_VB2_NS },
	{ "vb2_op", F_VB2_OP },
	{ "vb2_starved", F_VB2_STARVED },
	{ "vb2_num_buffers", F_VB2_NUM_BUFFERS },
	{ "vb2_queued", F_VB2_QUEUED },
	{ "vb2_drv_owned", F_VB2_DRV_OWNED },
	{ NULL, 0 },
};

static int sym_lookup(const struct symbol *tab, const char *name, long *out)
{
	for (; tab->name; tab++) {
		if (!strcmp(tab->name, name)) {
			*out = tab->value;
			return 0;
		}
	}
	return -1;
}

/* Resolve a scalar string to a long: numeric (base 0, allows -/0x) or symbolic
 * (kind/action/state names). */
static int resolve_value(const char *s, long *out)
{
	char *end = NULL;
	long v;

	if (!s || !*s)
		return -1;

	errno = 0;
	v = strtol(s, &end, 0);
	if (errno == 0 && end && *end == '\0') {
		*out = v;
		return 0;
	}
	if (!sym_lookup(kind_syms, s, out))
		return 0;
	if (!sym_lookup(enum_syms, s, out))
		return 0;
	return -1;
}

/* ---- libyaml document helpers -------------------------------------------- */

static const char *node_scalar(yaml_document_t *doc, yaml_node_t *n)
{
	(void)doc;
	if (n && n->type == YAML_SCALAR_NODE)
		return (const char *)n->data.scalar.value;
	return NULL;
}

static yaml_node_t *map_get(yaml_document_t *doc, yaml_node_t *map,
			    const char *key)
{
	yaml_node_pair_t *p;

	if (!map || map->type != YAML_MAPPING_NODE)
		return NULL;
	for (p = map->data.mapping.pairs.start;
	     p < map->data.mapping.pairs.top; p++) {
		yaml_node_t *k = yaml_document_get_node(doc, p->key);
		const char *ks = node_scalar(doc, k);

		if (ks && !strcmp(ks, key))
			return yaml_document_get_node(doc, p->value);
	}
	return NULL;
}

/* ---- cond parsing -------------------------------------------------------- */

static int parse_status_in(yaml_document_t *doc, yaml_node_t *seq,
			   struct diag_cond *c, char *err, size_t errsz)
{
	yaml_node_item_t *it;

	if (!seq || seq->type != YAML_SEQUENCE_NODE) {
		snprintf(err, errsz, "status_in must be a list");
		return -1;
	}
	for (it = seq->data.sequence.items.start;
	     it < seq->data.sequence.items.top; it++) {
		yaml_node_t *e = yaml_document_get_node(doc, *it);
		const char *s = node_scalar(doc, e);
		long v;

		if (!s || resolve_value(s, &v)) {
			snprintf(err, errsz, "bad status_in entry");
			return -1;
		}
		if (c->nstatus >= DIAG_MAX_STATUS) {
			snprintf(err, errsz, "too many status_in entries");
			return -1;
		}
		c->status_in[c->nstatus++] = v;
	}
	return 0;
}

static int add_match(struct diag_cond *c, const char *field, const char *valstr,
		     char *err, size_t errsz)
{
	long fid, val;
	enum diag_op op = OP_EQ;

	if (sym_lookup(field_syms, field, &fid)) {
		snprintf(err, errsz, "unknown field '%s'", field);
		return -1;
	}
	/* value prefix selects the operator: "!v" (NE), ">=v", "<=v"; else EQ */
	if (valstr[0] == '!') {
		op = OP_NE;
		valstr++;
	} else if (valstr[0] == '>' && valstr[1] == '=') {
		op = OP_GTE;
		valstr += 2;
	} else if (valstr[0] == '<' && valstr[1] == '=') {
		op = OP_LTE;
		valstr += 2;
	}
	if (resolve_value(valstr, &val)) {
		snprintf(err, errsz, "bad value '%s' for field '%s'", valstr,
			 field);
		return -1;
	}
	if (c->nmatch >= DIAG_MAX_MATCH) {
		snprintf(err, errsz, "too many match fields");
		return -1;
	}
	c->match[c->nmatch].field = (enum diag_field)fid;
	c->match[c->nmatch].value = val;
	c->match[c->nmatch].op = op;
	c->nmatch++;
	return 0;
}

/* Parse a "match: { field: value, ... }" mapping into cond->match[]. */
static int parse_match_map(yaml_document_t *doc, yaml_node_t *map,
			   struct diag_cond *c, char *err, size_t errsz)
{
	yaml_node_pair_t *p;

	if (!map || map->type != YAML_MAPPING_NODE) {
		snprintf(err, errsz, "match must be a mapping");
		return -1;
	}
	for (p = map->data.mapping.pairs.start;
	     p < map->data.mapping.pairs.top; p++) {
		yaml_node_t *k = yaml_document_get_node(doc, p->key);
		yaml_node_t *v = yaml_document_get_node(doc, p->value);
		const char *ks = node_scalar(doc, k);
		const char *vs = node_scalar(doc, v);

		if (!ks || !vs) {
			snprintf(err, errsz, "match entries must be scalars");
			return -1;
		}
		if (add_match(c, ks, vs, err, errsz))
			return -1;
	}
	return 0;
}

/* Parse a "when" item mapping (kind/match/status_in/within_ms/count_gte). */
static int parse_when(yaml_document_t *doc, yaml_node_t *item,
		      struct diag_cond *c, char *err, size_t errsz)
{
	yaml_node_t *n;
	const char *s;

	if (!item || item->type != YAML_MAPPING_NODE) {
		snprintf(err, errsz, "when item must be a mapping");
		return -1;
	}

	n = map_get(doc, item, "kind");
	if ((s = node_scalar(doc, n))) {
		long v;

		if (resolve_value(s, &v)) {
			snprintf(err, errsz, "bad kind '%s'", s);
			return -1;
		}
		c->has_kind = 1;
		c->kind = (uint32_t)v;
	}

	n = map_get(doc, item, "match");
	if (n && parse_match_map(doc, n, c, err, errsz))
		return -1;

	n = map_get(doc, item, "status_in");
	if (n && parse_status_in(doc, n, c, err, errsz))
		return -1;

	n = map_get(doc, item, "within_ms");
	if ((s = node_scalar(doc, n))) {
		c->has_within_ms = 1;
		c->within_ms = strtol(s, NULL, 0);
	}

	n = map_get(doc, item, "count_gte");
	if ((s = node_scalar(doc, n))) {
		c->has_count_gte = 1;
		c->count_gte = strtol(s, NULL, 0);
	}
	return 0;
}

/* Parse a trigger flow map: kind plus any other field as an equality match. */
static int parse_trigger(yaml_document_t *doc, yaml_node_t *map,
			 struct diag_cond *c, char *err, size_t errsz)
{
	yaml_node_pair_t *p;

	if (!map || map->type != YAML_MAPPING_NODE) {
		snprintf(err, errsz, "trigger must be a mapping");
		return -1;
	}
	for (p = map->data.mapping.pairs.start;
	     p < map->data.mapping.pairs.top; p++) {
		yaml_node_t *k = yaml_document_get_node(doc, p->key);
		yaml_node_t *v = yaml_document_get_node(doc, p->value);
		const char *ks = node_scalar(doc, k);
		const char *vs = node_scalar(doc, v);

		if (!ks || !vs) {
			snprintf(err, errsz, "trigger entries must be scalars");
			return -1;
		}
		if (!strcmp(ks, "kind")) {
			long v2;

			if (resolve_value(vs, &v2)) {
				snprintf(err, errsz, "bad kind '%s'", vs);
				return -1;
			}
			c->has_kind = 1;
			c->kind = (uint32_t)v2;
		} else if (add_match(c, ks, vs, err, errsz)) {
			return -1;
		}
	}
	if (!c->has_kind) {
		snprintf(err, errsz, "trigger requires a kind");
		return -1;
	}
	return 0;
}

static int parse_severity(const char *s)
{
	if (s) {
		if (!strcmp(s, "warn") || !strcmp(s, "warning"))
			return SEV_WARN;
		if (!strcmp(s, "error") || !strcmp(s, "err"))
			return SEV_ERROR;
	}
	return SEV_INFO;
}

static char *dup_scalar(yaml_document_t *doc, yaml_node_t *map, const char *key)
{
	const char *s = node_scalar(doc, map_get(doc, map, key));

	return s ? strdup(s) : NULL;
}

static int parse_deadline(yaml_document_t *doc, yaml_node_t *dl,
			  struct diag_rule *r, char *err, size_t errsz)
{
	const char *s;
	long v;

	r->type = RULE_DEADLINE;
	r->dl_reached_state = -1;
	r->dl_without_state = -1;

	s = node_scalar(doc, map_get(doc, dl, "reached_state"));
	if (!s || resolve_value(s, &v)) {
		snprintf(err, errsz, "deadline needs reached_state");
		return -1;
	}
	r->dl_reached_state = (int)v;

	s = node_scalar(doc, map_get(doc, dl, "without_state"));
	if (s && !resolve_value(s, &v))
		r->dl_without_state = (int)v;

	s = node_scalar(doc, map_get(doc, dl, "timeout_ms"));
	if (!s) {
		snprintf(err, errsz, "deadline needs timeout_ms");
		return -1;
	}
	r->dl_timeout_ms = strtol(s, NULL, 0);
	return 0;
}

static int parse_rule(yaml_document_t *doc, yaml_node_t *rn,
		      struct diag_rule *r, char *err, size_t errsz)
{
	yaml_node_t *n;

	memset(r, 0, sizeof(*r));

	r->id = dup_scalar(doc, rn, "id");
	r->name = dup_scalar(doc, rn, "name");
	r->conclusion = dup_scalar(doc, rn, "conclusion");
	r->fix = dup_scalar(doc, rn, "fix");
	r->severity = parse_severity(node_scalar(doc, map_get(doc, rn,
							      "severity")));
	if (!r->id) {
		snprintf(err, errsz, "rule missing id");
		return -1;
	}

	n = map_get(doc, rn, "deadline");
	if (n) {
		if (parse_deadline(doc, n, r, err, errsz))
			return -1;
		return 0;
	}

	r->type = RULE_EVENT;
	n = map_get(doc, rn, "trigger");
	if (parse_trigger(doc, n, &r->trigger, err, errsz))
		return -1;

	n = map_get(doc, rn, "when");
	if (n) {
		yaml_node_item_t *it;

		if (n->type != YAML_SEQUENCE_NODE) {
			snprintf(err, errsz, "when must be a list");
			return -1;
		}
		for (it = n->data.sequence.items.start;
		     it < n->data.sequence.items.top; it++) {
			yaml_node_t *item = yaml_document_get_node(doc, *it);

			if (r->nwhen >= DIAG_MAX_WHEN) {
				snprintf(err, errsz, "too many when conditions");
				return -1;
			}
			if (parse_when(doc, item, &r->when[r->nwhen], err,
				       errsz))
				return -1;
			r->nwhen++;
		}
	}
	return 0;
}

int diag_rules_parse(const char *text, size_t len, struct diag_rule **out,
		     char *err, size_t errsz)
{
	yaml_parser_t parser;
	yaml_document_t doc;
	yaml_node_t *root, *rules;
	yaml_node_item_t *it;
	struct diag_rule *arr = NULL;
	int n = 0;

	*out = NULL;
	if (!yaml_parser_initialize(&parser)) {
		snprintf(err, errsz, "yaml init failed");
		return -1;
	}
	yaml_parser_set_input_string(&parser, (const unsigned char *)text, len);

	if (!yaml_parser_load(&parser, &doc)) {
		snprintf(err, errsz, "YAML parse error at line %zu: %s",
			 (size_t)parser.problem_mark.line + 1,
			 parser.problem ? parser.problem : "?");
		yaml_parser_delete(&parser);
		return -1;
	}

	root = yaml_document_get_root_node(&doc);
	if (!root) {
		snprintf(err, errsz, "empty document");
		goto fail;
	}
	rules = map_get(&doc, root, "rules");
	if (!rules || rules->type != YAML_SEQUENCE_NODE) {
		snprintf(err, errsz, "top-level 'rules:' list required");
		goto fail;
	}

	arr = calloc(DIAG_MAX_RULES, sizeof(*arr));
	if (!arr) {
		snprintf(err, errsz, "out of memory");
		goto fail;
	}

	for (it = rules->data.sequence.items.start;
	     it < rules->data.sequence.items.top; it++) {
		yaml_node_t *rn = yaml_document_get_node(&doc, *it);

		if (n >= DIAG_MAX_RULES) {
			ut_warn("diag: rule limit %d reached, ignoring rest",
				DIAG_MAX_RULES);
			break;
		}
		if (parse_rule(&doc, rn, &arr[n], err, errsz)) {
			diag_rules_free(arr, n);
			arr = NULL;
			goto fail;
		}
		n++;
	}

	yaml_document_delete(&doc);
	yaml_parser_delete(&parser);
	*out = arr;
	return n;

fail:
	yaml_document_delete(&doc);
	yaml_parser_delete(&parser);
	return -1;
}

int diag_rules_load_file(const char *path, struct diag_rule **out, char *err,
			 size_t errsz)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long sz;
	size_t got;
	int rc;

	if (!f) {
		snprintf(err, errsz, "cannot open %s: %s", path,
			 strerror(errno));
		return -1;
	}
	if (fseek(f, 0, SEEK_END) || (sz = ftell(f)) < 0) {
		snprintf(err, errsz, "cannot size %s", path);
		fclose(f);
		return -1;
	}
	rewind(f);
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		snprintf(err, errsz, "out of memory");
		fclose(f);
		return -1;
	}
	got = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	buf[got] = '\0';

	rc = diag_rules_parse(buf, got, out, err, errsz);
	free(buf);
	return rc;
}

int diag_rules_load_default(struct diag_rule **out, char *err, size_t errsz)
{
	return diag_rules_parse(rules_default_yaml,
				sizeof(rules_default_yaml) - 1, out, err,
				errsz);
}
