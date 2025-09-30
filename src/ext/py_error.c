// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pypam.h"

typedef struct {
	int value;
	const char *name;
} intenum_entry_t;

/**
 * @brief Lookup table for PAM codes / names.
 *
 * This comments from pam library and numeric values in a comment
 * above each entry to make it somewhat easier for developers to
 * understand what's going on.
 *
 * @note like errnos, the meaning of PAM codes depends on the context
 * in which they are returned. The PAM application API / manpages
 * give more verbose descriptions of what they mean as response to
 * a pam function call.
 *
 * @note this is from a shared header file between PAM applications
 * (client) and the PAM service module (servers). Some of the following
 * will never be returned to clients.
 */

static const intenum_entry_t pam_code_tbl[] = {
	// 0	Successful function return
	{ PAM_SUCCESS, "PAM_SUCCESS" },

	// 1	dlopen() failure when dynamically loading a service module
	{ PAM_OPEN_ERR, "PAM_OPEN_ERR" },

	// 2	Symbol not found
	{ PAM_SYMBOL_ERR, "PAM_SYMBOL_ERR" },

	// 3	Error in service module
	{ PAM_SERVICE_ERR, "PAM_SERVICE_ERR" },

	// 4	System error
	{ PAM_SYSTEM_ERR, "PAM_SYSTEM_ERR" },

	// 5	Memory buffer error
	{ PAM_BUF_ERR, "PAM_BUF_ERR" },

	// 6	Permission denied
	{ PAM_PERM_DENIED, "PAM_PERM_DENIED" },

	// 7	Authentication failure
	{ PAM_AUTH_ERR, "PAM_AUTH_ERR" },

	// 8	Can not access authentication data due to insufficient credentials
	{ PAM_CRED_INSUFFICIENT, "PAM_CRED_INSUFFICIENT" },

	// 9	Underlying authentication service can not retrieve authentication information
	{ PAM_AUTHINFO_UNAVAIL, "PAM_AUTHINFO_UNAVAIL" },

	// 10	User not known to the underlying authentication module
	{ PAM_USER_UNKNOWN, "PAM_USER_UNKNOWN" },

	// 11	An authentication service has maintained a retry count which has been reached.
	{  PAM_MAXTRIES, "PAM_MAXTRIES" },

	// 12	New authentication token required. This is normally returned if the
	//	machine security policies require that the password should be changed.
	{ PAM_NEW_AUTHTOK_REQD, "PAM_NEW_AUTHTOK_REQD" },

	// 13	User account has expired
	{ PAM_ACCT_EXPIRED, "PAM_ACCT_EXPIRED" },

	// 14	Can not make/remove an entry for the specified session
	{ PAM_SESSION_ERR, "PAM_SESSION_ERR" },

	// 15	Underlying authentication service can not retrieve user credentials
	{ PAM_CRED_UNAVAIL, "PAM_CRED_UNAVAIL" },

	// 16	User credentials expired
	{ PAM_CRED_EXPIRED, "PAM_CRED_EXPIRED" },

	// 17	Failure setting user credentials
	{ PAM_CRED_ERR, "PAM_CRED_ERR" },

	// 18	No module specific data is present
	{ PAM_NO_MODULE_DATA, "PAM_NO_MODULE_DATA" },

	// 19	Conversation error
	{ PAM_CONV_ERR, "PAM_CONV_ERR" },

	// 20	Authentication token manipulation error
	{ PAM_AUTHTOK_ERR, "PAM_AUTHTOK_ERR" },

	// 21	Authentication information cannot be recovered
	{ PAM_AUTHTOK_RECOVERY_ERR, "PAM_AUTHTOK_RECOVERY_ERR" },

	// 22	Authentication token lock busy
	{ PAM_AUTHTOK_LOCK_BUSY, "PAM_AUTHTOK_LOCK_BUSY" },

	// 23	Authentication token aging disabled
	{ PAM_AUTHTOK_DISABLE_AGING, "PAM_AUTHTOK_DISABLE_AGING" },

	// 24	Preliminary check by password service
	{ PAM_TRY_AGAIN, "PAM_TRY_AGAIN" },

	// 25	Ignore underlying account module
	{ PAM_IGNORE, "PAM_IGNORE" },

	// 26	Critical error (?module fail now request)
	{ PAM_ABORT, "PAM_ABORT" },

	// 27	user's authentication token has expired
	{ PAM_AUTHTOK_EXPIRED, "PAM_AUTHTOK_EXPIRED" },

	// 28	module is unknown
	{ PAM_MODULE_UNKNOWN, "PAM_MODULE_UNKNOWN" },

	// 29	Bad item passed to pam_*_item()
	{ PAM_BAD_ITEM, "PAM_BAD_ITEM" },

	// 30	conversation function is event driven and data is not available yet
	{ PAM_CONV_AGAIN, "PAM_CONV_AGAIN" },

	// 31	please call this function again to complete authentication stack. Before
	// 	calling again, verify that conversation is completed
	{ PAM_INCOMPLETE, "PAM_INCOMPLETE" },
};

_Static_assert(
	_PAM_RETURN_VALUES == ARRAY_SIZE(pam_code_tbl),
	"PAM code lookup table needs updating - last value changed"
);

const char *py_pamcode_to_string(int code)
{
	for (size_t i = 0; i < ARRAY_SIZE(pam_code_tbl); i++) {
		if (pam_code_tbl[i].value == code) {
			return pam_code_tbl[i].name;
		}
	}

	PYPAM_ASSERT(
		(code >= PAM_SUCCESS || code <= PAM_INCOMPLETE),
		"Unexpected PAM code"
	);

	// This is impossible to hit but we're making compiler happy
	return "UNKNOWN_ERROR";
}

PyObject *py_pamcode_dict(void)
{
	PyObject *code_dict = PyDict_New();
	if (!code_dict) {
		return NULL;
	}

	for (size_t i = 0; i < ARRAY_SIZE(pam_code_tbl); i++) {
		PyObject *code_obj = PyLong_FromLong(pam_code_tbl[i].value);
		PyObject *name_obj = PyUnicode_FromString(pam_code_tbl[i].name);

		if (!code_obj || !name_obj) {
			Py_XDECREF(code_obj);
			Py_XDECREF(name_obj);
			Py_DECREF(code_dict);
			return NULL;
		}

		if (PyDict_SetItem(code_dict, code_obj, name_obj) < 0) {
			Py_DECREF(code_obj);
			Py_DECREF(name_obj);
			Py_DECREF(code_dict);
			return NULL;
		}

		Py_DECREF(code_obj);
		Py_DECREF(name_obj);
	}

	return code_dict;
}

static PyObject *
create_pam_code_enum(void)
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

	for (i = 0; i < ARRAY_SIZE(pam_code_tbl); i++) {
		PyObject *py_value = PyLong_FromLong(pam_code_tbl[i].value);
		if (py_value == NULL ||
		    PyDict_SetItemString(enum_dict, pam_code_tbl[i].name,
					 py_value) < 0) {
			Py_XDECREF(py_value);
			Py_DECREF(enum_dict);
			Py_DECREF(int_enum_class);
			return NULL;
		}
		Py_DECREF(py_value);
	}

	py_enum_name = PyUnicode_FromString(MODULE_NAME ".PAMCode");
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

PyDoc_STRVAR(py_pam_exception__doc__,
"PAMError(Exception)\n"
"-----------------------\n\n"
"Python wrapper around an unexpected PAM response code.\n\n"
"attributes:\n"
"-----------\n"
"code: int\n"
"    PAM response code\n"
"name: str\n"
"    Human-readable name of the response code\n"
"err_str: str\n"
"    pam_strerror for the error code\n"
"message: str\n"
"    verbose message describing the error\n"
"location: str\n"
"    line of file in uncompiled source of this module\n\n"
);
bool setup_pam_exception(PyObject *module_ref)
{
	tnpam_state_t *state = NULL;
	PyObject *pam_error = NULL;
	PyObject *dict = NULL;
	PyObject *pam_code_enum = NULL;
	bool success = false;

	// Set up spec for the new exception type
	dict = Py_BuildValue("{s:i,s:s,s:s,s:s,s:s}",
			     "code", PAM_SUCCESS,
			     "name", "",
			     "err_str", "",
			     "message", "",
			     "location", "");
	if (dict == NULL) {
		goto cleanup;
	}

	pam_error = PyErr_NewExceptionWithDoc(MODULE_NAME
					      ".PAMError",
					      py_pam_exception__doc__,
					      PyExc_RuntimeError,
					      dict);
	if (pam_error == NULL) {
		goto cleanup;
	}

	state = (tnpam_state_t *)PyModule_GetState(module_ref);
	if (state == NULL) {
		goto cleanup;
	}

	// Add reference to our module state so that it's available generally
	// for implementation in this extension
	state->pam_error = Py_NewRef(pam_error);

	// Add exception reference to root of module so that it's available
	// to library consumers
	if (PyModule_AddObjectRef(module_ref, "PAMError", pam_error) < 0) {
		goto cleanup;
	}

	// Create and add PAMCode IntEnum
	pam_code_enum = create_pam_code_enum();
	if (pam_code_enum == NULL) {
		goto cleanup;
	}

	if (PyModule_AddObjectRef(module_ref, "PAMCode", pam_code_enum) < 0) {
		goto cleanup;
	}

	// Store reference in module state
	state->pam_code_enum = Py_NewRef(pam_code_enum);

	success = true;

cleanup:
	Py_CLEAR(dict);
	Py_CLEAR(pam_error);
	Py_CLEAR(pam_code_enum);
	return success;
}

void
_set_pam_exc(int code, const char *additional_info, const char *location)
{
	tnpam_state_t *state = NULL;
	PyObject *obj = NULL;
	PyObject *exc = NULL;
	PyObject *message = NULL;
	PyObject *enum_member = NULL;
	const char *err_str = pam_strerror(NULL, code);  // linux-pam doesn't actually use the first arg
	const char *name = py_pamcode_to_string(code);

	state = py_get_pam_state(NULL);
	if (state == NULL) {
		return;
	}

	// first set up str() for exception
	message = PyUnicode_FromFormat("[%s]: %s", name, additional_info);
	if (message == NULL) {
		return;
	}

	PYPAM_ASSERT((state->pam_error != NULL), "Pam error not initialized");
	exc = PyObject_CallOneArg(state->pam_error, message);
	Py_CLEAR(message);
	if (exc == NULL) {
		return;
	}

	/* set error code as PAMCode enum member */
	PYPAM_ASSERT((state->pam_code_enum != NULL), "PAMCode enum not initialized");

	// Create integer object for the code value
	obj = PyLong_FromLong(code);
	if (obj == NULL) {
		Py_CLEAR(exc);
		return;
	}

	// Get the enum member: PAMCode(code)
	enum_member = PyObject_CallFunctionObjArgs(state->pam_code_enum, obj, NULL);
	Py_DECREF(obj);

	if (enum_member == NULL) {
		Py_CLEAR(exc);
		return;
	}

	PyObject_SetAttrString(exc, "code", enum_member);
	Py_CLEAR(enum_member);

	/* set name */
	obj = PyUnicode_FromString(name);
	if (obj == NULL) {
		Py_CLEAR(exc);
		return;
	}

	PyObject_SetAttrString(exc, "name", obj);
	Py_CLEAR(obj);

	/* set err_str */
	obj = PyUnicode_FromString(err_str);
	if (obj == NULL) {
		Py_CLEAR(exc);
		return;
	}

	PyObject_SetAttrString(exc, "err_str", obj);
	Py_CLEAR(obj);

	/* set message */
	obj = PyUnicode_FromString(additional_info);
	if (obj == NULL) {
		Py_CLEAR(exc);
		return;
	}

	PyObject_SetAttrString(exc, "message", obj);
	Py_CLEAR(obj);

	/* set location */
	obj = PyUnicode_FromString(location);
	if (obj == NULL) {
		Py_CLEAR(exc);
		return;
	}

	PyObject_SetAttrString(exc, "location", obj);
	Py_CLEAR(obj);

	PyErr_SetObject(state->pam_error, exc);
}
