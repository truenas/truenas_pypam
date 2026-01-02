// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pypam.h"

typedef struct {
	int value;
	const char *name;
} cred_op_entry_t;

/**
 * @brief Lookup table for PAM credential operation flags from pam_setcred(3).
 *
 * These flags specify the type of credential operation to perform.
 * Any flag may be logically OR'd with PAM_SILENT.
 */
static const cred_op_entry_t cred_op_tbl[] = {
	// Initialize the credentials for the user
	{ PAM_ESTABLISH_CRED, "PAM_ESTABLISH_CRED" },

	// Delete the user's credentials
	{ PAM_DELETE_CRED, "PAM_DELETE_CRED" },

	// Fully reinitialize the user's credentials
	{ PAM_REINITIALIZE_CRED, "PAM_REINITIALIZE_CRED" },

	// Extend the lifetime of the existing credentials
	{ PAM_REFRESH_CRED, "PAM_REFRESH_CRED" },
};

static bool
is_valid_cred_op(int flags)
{
	// Remove PAM_SILENT flag for validation
	int op_flags = flags & ~PAM_SILENT;

	for (size_t i = 0; i < ARRAY_SIZE(cred_op_tbl); i++) {
		if (cred_op_tbl[i].value == op_flags) {
			return true;
		}
	}
	return false;
}

static PyObject *
create_cred_op_enum(void)
{
	PyObject *enum_module = NULL;
	PyObject *int_enum_class = NULL;
	PyObject *enum_dict = NULL;
	PyObject *py_enum_name = NULL;
	PyObject *result_enum = NULL;
	size_t i;

	// Import enum module and get IntEnum class
	enum_module = PyImport_ImportModule("enum");
	if (enum_module == NULL) {
		return NULL;
	}

	int_enum_class = PyObject_GetAttrString(enum_module, "IntEnum");
	Py_DECREF(enum_module);
	if (int_enum_class == NULL) {
		return NULL;
	}

	// Create enum dictionary
	enum_dict = PyDict_New();
	if (enum_dict == NULL) {
		Py_DECREF(int_enum_class);
		return NULL;
	}

	for (i = 0; i < ARRAY_SIZE(cred_op_tbl); i++) {
		PyObject *py_value = PyLong_FromLong(cred_op_tbl[i].value);
		if (py_value == NULL ||
		    PyDict_SetItemString(enum_dict, cred_op_tbl[i].name,
					 py_value) < 0) {
			Py_XDECREF(py_value);
			Py_DECREF(enum_dict);
			Py_DECREF(int_enum_class);
			return NULL;
		}
		Py_DECREF(py_value);
	}

	py_enum_name = PyUnicode_FromString(MODULE_NAME ".CredOp");
	if (py_enum_name == NULL) {
		Py_DECREF(enum_dict);
		Py_DECREF(int_enum_class);
		return NULL;
	}

	result_enum = PyObject_CallFunction(int_enum_class, "OO",
					    py_enum_name, enum_dict);

	Py_DECREF(py_enum_name);
	Py_DECREF(enum_dict);
	Py_DECREF(int_enum_class);

	return result_enum;
}


PyObject *py_tnpam_setcred(tnpam_ctx_t *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"operation", "silent", NULL};
	PyObject *operation = NULL;
	boolean_t silent = B_FALSE;
	int flags;
	pamcode_t retval;
	tnpam_state_t *state = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$Op", kwlist,
					 &operation, &silent)) {
		return NULL;
	}

	if (operation == NULL) {
		PyErr_SetString(PyExc_TypeError, "operation is required");
		return NULL;
	}

	state = py_get_pam_state(NULL);
	if (state == NULL) {
		return NULL;
	}

	PYPAM_ASSERT((state->cred_op_enum != NULL), "CredOp enum not initialized");

	// Validate that operation is an instance of CredOp enum
	if (!PyObject_IsInstance(operation, state->cred_op_enum)) {
		PyErr_SetString(PyExc_TypeError,
				"operation must be a CredOp enum member");
		return NULL;
	}

	// Extract integer value from CredOp enum
	flags = PyLong_AsLong(operation);
	if (flags == -1 && PyErr_Occurred()) {
		return NULL;
	}

	// Add PAM_SILENT flag if requested
	if (silent) {
		flags |= PAM_SILENT;
	}

	// Validate that this is a valid PAM credential operation
	if (!is_valid_cred_op(flags)) {
		PyErr_SetString(PyExc_ValueError,
				"Invalid PAM credential operation");
		return NULL;
	}

	// Audit the credential operation
	// Include both the user and the operation type
	if (PySys_Audit(MODULE_NAME ".setcred", "OO", self->user, operation) < 0) {
		return NULL;
	}

	PYPAM_LOCK(self);
	retval = pam_setcred(self->hdl, flags);
	self->last_pam_result = retval;
	PYPAM_UNLOCK(self);

	if (retval != PAM_SUCCESS) {
		if (!PyErr_Occurred()) {
			set_pam_exc(retval, "pam_setcred() failed");
		}
		return NULL;
	}

	Py_RETURN_NONE;
}

bool setup_cred_op_enum(PyObject *module_ref)
{
	tnpam_state_t *state = NULL;
	PyObject *cred_op_enum = NULL;

	state = py_get_pam_state(module_ref);
	if (state == NULL) {
		return false;
	}

	// Create and add CredOp IntEnum
	cred_op_enum = create_cred_op_enum();
	if (cred_op_enum == NULL) {
		return false;
	}

	if (PyModule_AddObjectRef(module_ref, "CredOp", cred_op_enum) < 0) {
		Py_DECREF(cred_op_enum);
		return false;
	}

	// Store reference in module state
	state->cred_op_enum = cred_op_enum;

	return true;
}
