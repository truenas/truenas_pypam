// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pypam.h"

PyObject *
py_tnpam_open_session(tnpam_ctx_t *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = { "silent", NULL };
	boolean_t silent = B_FALSE;
	int flags = 0;
	pamcode_t ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$p", kwlist,
					 &silent)) {
		return NULL;
	}

	if (silent) {
		flags |= PAM_SILENT;
	}

	if (!self->authenticated) {
		PyErr_SetString(PyExc_ValueError,
				"pam_authenticate has not been successfully "
				"called on pam handle.");
		return NULL;
	}

	if (self->session_opened) {
		PyErr_SetString(PyExc_ValueError,
				"session is already opened for this handle.");
		return NULL;
	}

	// Audit the session opening
	if (PySys_Audit(MODULE_NAME ".open_session", "O", self->user) < 0) {
		return NULL;
	}

	if (!tnpam_call_pam_op(self, pam_open_session, flags, &ret)) {
		return NULL;
	}

	if (ret != PAM_SUCCESS) {
		if (!PyErr_Occurred()) {
			set_pam_exc(ret, "pam_open_session() failed");
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

	self->session_opened = B_TRUE;

	Py_RETURN_NONE;
}

PyObject *
py_tnpam_close_session(tnpam_ctx_t *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = { "silent", NULL };
	boolean_t silent = B_FALSE;
	int flags = 0;
	pamcode_t ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$p", kwlist,
					 &silent)) {
		return NULL;
	}

	if (silent) {
		flags |= PAM_SILENT;
	}

	if (!self->session_opened) {
		PyErr_SetString(PyExc_ValueError,
				"session is not opened for this handle.");
		return NULL;
	}

	// Audit the session closing
	if (PySys_Audit(MODULE_NAME ".close_session", "O", self->user) < 0) {
		return NULL;
	}

	if (!tnpam_call_pam_op(self, pam_close_session, flags, &ret)) {
		return NULL;
	}

	if (ret != PAM_SUCCESS) {
		if (!PyErr_Occurred()) {
			set_pam_exc(ret, "pam_close_session() failed");
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

	self->session_opened = B_FALSE;

	Py_RETURN_NONE;
}
