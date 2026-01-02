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