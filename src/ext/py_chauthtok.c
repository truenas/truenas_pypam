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
	 * A password change is interactive -- pam_unix prompts for the new token
	 * via pam_get_authtok() -- so unlike account management and session
	 * setup it cannot use the collector conversation, which answers every
	 * prompt with NULL. On an internal-thread context there is no way to
	 * reach the prompt, so refuse rather than park on it holding the handle.
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

	/*
	 * A conversation callback can leave an exception pending even when
	 * the stack returns PAM_SUCCESS; see py_tnpam_authenticate().
	 */
	if (PyErr_Occurred()) {
		return NULL;
	}

	Py_RETURN_NONE;
}