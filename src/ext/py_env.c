// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pypam.h"

// WARNING: PAM environment variables should not be used to store
// sensitive information. Depending on application they may end up
// merged into the application's overall env.

PyObject *
py_tnpam_setenv(tnpam_ctx_t *self, PyObject *args, PyObject *kwds)
{
	// set the value of the specified environmental variable
	static char *kwlist[] = {
		"name",
		"value",
		"readonly",
		NULL
	};
	boolean_t ro = B_FALSE;
	const char *cname = NULL;
	const char *cvalue = NULL;
	PyObject *pyval = NULL;
	pamcode_t ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$sOp", kwlist,
					 &cname,
					 &pyval,
					 &ro)) {
		return NULL;
	}

	if (cname == NULL) {
		PyErr_SetString(PyExc_ValueError,
				"\"name\" is required.");
		return NULL;
	}

	// Py_None and omitted "value" are both interpreted as intention to
	// remove the environmental variable by setting to NULL
	if (pyval && (pyval != Py_None)) {
		cvalue = PyUnicode_AsUTF8(pyval);
		if (cvalue == NULL) {
			return NULL;
		}
	}

	PYPAM_LOCK(self);
	if (cvalue == NULL)
		// pam_misc_setenv can't be used to actually remove
		// a pam environmental variable
		ret = pam_putenv(self->hdl, cname);
	else
		ret = pam_misc_setenv(self->hdl, cname, cvalue, ro);
	PYPAM_UNLOCK(self);

	if (ret != PAM_SUCCESS) {
		set_pam_exc(ret, "pam_misc_setenv() failed");
		return NULL;
	}

	Py_RETURN_NONE;
}

PyObject *
py_tnpam_getenv(tnpam_ctx_t *self, PyObject *args, PyObject *kwds)
{
	// get value of the specified environmental variable
	static char *kwlist[] = {"name", NULL};
	const char *cname = NULL;
	const char *value = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist,
					 &cname)) {
		return NULL;
	}

	PYPAM_LOCK(self);
	value = pam_getenv(self->hdl, cname);
	PYPAM_UNLOCK(self);

	if (value == NULL) {
		PyErr_Format(PyExc_FileNotFoundError,
			     "%s: pam environmental variable not set",
			     cname);
		return NULL;
	}

	return PyUnicode_FromString(value);
}


PyObject *
py_tnpam_envlist(tnpam_ctx_t *self, PyObject *Py_UNUSED(ignored))
{
	// convert pam environment variable list to dict
	char **pamenv = NULL;
	char *envar;
	PyObject *out = NULL;
	int i;
	int err;

	/*
	 * An empty environment comes back as a valid array whose first element
	 * is NULL. pam_getenvlist() returns NULL only on failure: no handle, a
	 * missing or corrupt environment, or an allocation failure in
	 * _copy_env() (libpam/pam_env.c).
	 *
	 * errno must be captured before PYPAM_UNLOCK, which releases the handle
	 * and reacquires the GIL; neither is required to preserve it.
	 */
	PYPAM_LOCK(self);
	errno = 0;
	pamenv = pam_getenvlist(self->hdl);
	err = errno;
	PYPAM_UNLOCK(self);

	if (pamenv == NULL) {
		if (err == ENOMEM) {
			return PyErr_NoMemory();
		}
		PyErr_SetString(PyExc_RuntimeError,
				"pam_getenvlist() failed: the PAM environment "
				"is unavailable or corrupt");
		return NULL;
	}

	out = PyDict_New();
	if (out == NULL) {
		goto cleanup;
	}

	for (i = 0, envar = *pamenv; (envar = pamenv[i]) != NULL; i++) {
		// malloced NULL-terminated strings of format
		// key=value
		char *cval = strchr(envar, '=');
		PyObject *pyval = NULL;
		int ret;
		if (cval == NULL)
			continue;

		// separate the key and value
		*cval = '\0';
		cval++;
		if (*cval == '\0')
			continue;

		pyval = PyUnicode_FromString(cval);
		if (pyval == NULL) {
			Py_CLEAR(out);
			goto cleanup;
		}

		ret = PyDict_SetItemString(out, envar, pyval);
		Py_DECREF(pyval);
		if (ret == -1) {
			Py_CLEAR(out);
			goto cleanup;
		}
	}

cleanup:
	for (i = 0, envar = *pamenv; (envar = pamenv[i]) != NULL; i++) {
		free(envar);
		envar = NULL;
	}

	free(pamenv);
	return out;
}
