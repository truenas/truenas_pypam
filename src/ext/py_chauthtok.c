// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pypam.h"

PyObject *
py_tnpam_chauthtok(tnpam_ctx_t *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"silent",
		"change_expired_authtok",
		NULL
	};
	boolean_t silent = B_FALSE;
	boolean_t change_expired_authtok = B_FALSE;
	int flags = 0;
	pamcode_t ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$pp", kwlist,
					 &silent,
					 &change_expired_authtok)) {
		return NULL;
	}

	if (silent) {
		flags |= PAM_SILENT;
	}

	if (change_expired_authtok) {
		flags |= PAM_CHANGE_EXPIRED_AUTHTOK;
	}

	/*
	 * Unlike account management and session setup, a password change is
	 * inherently interactive -- pam_unix always prompts for the new token
	 * via pam_get_authtok(). On an internal-thread context the installed
	 * conversation parks the calling thread waiting for a response only
	 * continue_authentication() can deliver, and the caller is the thread
	 * that would have to deliver it, so the call would hang forever holding
	 * the handle. Answering the prompt with a collector instead would just
	 * fail the change with a confusing error, so refuse up front.
	 */
	if (self->conv_type == TNPAM_CONV_INTERNAL_THREAD) {
		PyErr_SetString(PyExc_RuntimeError,
				"chauthtok() requires a context created with a "
				"conversation_function; a password change is "
				"interactive and cannot be driven by "
				"begin_authentication()/continue_authentication()");
		return NULL;
	}

	// Audit the password change attempt
	if (PySys_Audit(MODULE_NAME ".chauthtok", "O", self->user) < 0) {
		return NULL;
	}

	PYPAM_LOCK(self);
	ret = pam_chauthtok(self->hdl, flags);
	self->last_pam_result = ret;
	PYPAM_UNLOCK(self);

	if (ret != PAM_SUCCESS) {
		if (!PyErr_Occurred()) {
			set_pam_exc(ret, "pam_chauthtok() failed");
		}
		return NULL;
	}

	Py_RETURN_NONE;
}