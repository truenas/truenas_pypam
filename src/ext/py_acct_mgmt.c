// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pypam.h"

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
		 * temporarily swap in tnpam_discard_conv for this call.
		 */
		struct pam_conv discard_conv = {
			.conv = tnpam_discard_conv,
			.appdata_ptr = NULL,
		};
		PYPAM_LOCK(self);
		pam_set_item(self->hdl, PAM_CONV, &discard_conv);
		ret = pam_acct_mgmt(self->hdl, flags);
		self->last_pam_result = ret;
		pam_set_item(self->hdl, PAM_CONV, &self->conv);
		PYPAM_UNLOCK(self);
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
