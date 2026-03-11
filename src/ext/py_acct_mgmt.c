// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pypam.h"

/*
 * Upper bound on the number of PAM messages we collect from a single
 * pam_acct_mgmt() call in internal-thread mode.  pam_acct_mgmt() only
 * emits informational messages (PAM_TEXT_INFO / PAM_ERROR_MSG), never
 * interactive prompts, so one or two messages per call is typical and
 * eight is well beyond what any real module sends.
 */
#define ACCT_MSG_BUF 8

struct tnpam_acct_msgs {
	int count;
	int msg_styles[ACCT_MSG_BUF];
	char *msgs[ACCT_MSG_BUF];
};

/*
 * Conversation function used during pam_acct_mgmt() in internal-thread
 * mode.  It must not block (unlike tnpam_internal_conv, which waits for
 * the main thread) and must not touch Python objects (the GIL is not
 * held).  It copies each message string into the tnpam_acct_msgs buffer
 * using PyMem_RawMalloc (GIL-free) so the caller can convert them to
 * Python objects after reacquiring the GIL.
 *
 * Note: *resp is allocated with calloc, not PyMem_Raw*, because libpam
 * owns and frees it with free().
 *
 * Responses are zero-filled; PAM_TEXT_INFO / PAM_ERROR_MSG messages do
 * not require a meaningful response string.
 */
static int
tnpam_acct_collect_conv(int num_msg, const struct pam_message **msg,
			struct pam_response **resp, void *appdata_ptr)
{
	struct tnpam_acct_msgs *col = appdata_ptr;
	int i;

	*resp = calloc(num_msg, sizeof(struct pam_response));
	if (*resp == NULL) {
		return PAM_BUF_ERR;
	}

	for (i = 0; i < num_msg; i++) {
		const char *src = msg[i]->msg ? msg[i]->msg : "";
		size_t len = strlen(src) + 1;
		char *copy;

		if (col->count >= ACCT_MSG_BUF) {
			break;
		}

		copy = PyMem_RawMalloc(len);
		if (copy == NULL) {
			/* OOM — skip this message rather than abort */
			continue;
		}
		memcpy(copy, src, len);
		col->msg_styles[col->count] = msg[i]->msg_style;
		col->msgs[col->count] = copy;
		col->count++;
	}

	return PAM_SUCCESS;
}

PyObject *
py_tnpam_acct_mgmt(tnpam_ctx_t *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"silent",
		"disallow_null_authtok",
		NULL
	};
	boolean_t silent = B_FALSE;
	boolean_t disallow_null_authtok = B_FALSE;
	int flags = 0;
	pamcode_t ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$pp", kwlist,
					 &silent,
					 &disallow_null_authtok)) {
		return NULL;
	}

	if (silent) {
		flags |= PAM_SILENT;
	}

	if (disallow_null_authtok) {
		flags |= PAM_DISALLOW_NULL_AUTHTOK;
	}

	// Audit the account management check
	if (PySys_Audit(MODULE_NAME ".acct_mgmt", "O", self->user) < 0) {
		return NULL;
	}

	if (self->conv_type == TNPAM_CONV_INTERNAL_THREAD) {
		/*
		 * In internal thread mode the PAM conv is tnpam_internal_conv,
		 * which blocks waiting for the main thread. acct_mgmt() is
		 * synchronous and only emits informational messages, so we
		 * temporarily swap in tnpam_acct_collect_conv, which captures
		 * message strings into a C buffer without blocking.  After
		 * reacquiring the GIL we convert them to Python and append a
		 * tuple to th_cb.messages so callers can inspect acct_mgmt
		 * messages (e.g. "Your account has expired").
		 */
		struct tnpam_acct_msgs collected = {0};
		struct pam_conv collect_conv = {
			.conv = tnpam_acct_collect_conv,
			.appdata_ptr = &collected,
		};
		PYPAM_LOCK(self);
		pam_set_item(self->hdl, PAM_CONV, &collect_conv);
		ret = pam_acct_mgmt(self->hdl, flags);
		self->last_pam_result = ret;
		pam_set_item(self->hdl, PAM_CONV, &self->conv);
		PYPAM_UNLOCK(self);

		/* GIL reacquired — convert collected C strings to Python. */
		if (collected.count > 0) {
			struct pam_message msgs_tmp[ACCT_MSG_BUF];
			const struct pam_message *msgs_ptr[ACCT_MSG_BUF];
			PyObject *pymsg;
			int i;

			for (i = 0; i < collected.count; i++) {
				msgs_tmp[i].msg_style = collected.msg_styles[i];
				msgs_tmp[i].msg = collected.msgs[i];
				msgs_ptr[i] = &msgs_tmp[i];
			}

			pymsg = py_pam_messages_parse(collected.count, msgs_ptr);
			if (pymsg != NULL) {
				if (PyList_Append(self->conv_data.th_cb.messages, pymsg) < 0) {
					PyErr_Clear();
				}
				Py_DECREF(pymsg);
			} else {
				PyErr_Clear();
			}

			for (i = 0; i < collected.count; i++) {
				PyMem_RawFree(collected.msgs[i]);
			}
		}
	} else {
		PYPAM_LOCK(self);
		ret = pam_acct_mgmt(self->hdl, flags);
		self->last_pam_result = ret;
		PYPAM_UNLOCK(self);
	}

	if (ret != PAM_SUCCESS) {
		if (!PyErr_Occurred()) {
			set_pam_exc(ret, "pam_acct_mgmt() failed");
		}
		return NULL;
	}

	Py_RETURN_NONE;
}
