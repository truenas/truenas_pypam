// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pypam.h"

PyObject *
py_tnpam_authenticate(tnpam_ctx_t *self, PyObject *args, PyObject *kwds)
{
	// Wrapper around pam_authenticate(3)
	// Multi-step authentication will be handled throuh the callback
	// function specified when creating the PAM context object.
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

	// Audit the authentication attempt
	if (PySys_Audit(MODULE_NAME ".authenticate", "O", self->user) < 0) {
		return NULL;
	}

	PYPAM_LOCK(self);
	ret = pam_authenticate(self->hdl, flags);
	self->last_pam_result = ret;
	PYPAM_UNLOCK(self);

	if (ret != PAM_SUCCESS) {
		if (!PyErr_Occurred()) {
			set_pam_exc(ret, "pam_authenticate() failed");
		}
		return NULL;
	}

	self->authenticated = B_TRUE;
	Py_RETURN_NONE;
}
