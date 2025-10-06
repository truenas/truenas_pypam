// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "truenas_pypam.h"

PyDoc_STRVAR(tnpam_get_context__doc__,
"get_context(service_name='login', *, user, conversation_function,\n"
"            conversation_private_data=None, confdir=None, rhost=None,\n"
"            ruser=None, fail_delay=0) -> PamContext\n"
"-------------------------------------------------------------------\n\n"
"Create a new PAM context for user authentication and session management.\n\n"
"This function creates a PAM context by calling pam_start_confdir(3) and\n"
"initializes various PAM items using pam_set_item(3). The context can be\n"
"used for authentication, session management, and environment variable\n"
"operations.\n\n"
"Parameters\n"
"----------\n"
"service_name : str, optional\n"
"    Name of the PAM service (default='login'). The policy for this service\n"
"    will be read from /etc/pam.d/service_name or /etc/pam.conf.\n"
"    See pam_start(3).\n"
"user : str\n"
"    Username for authentication (stored as PAM_USER item)\n"
"conversation_function : callable\n"
"    Callback function for PAM conversation mechanism. Must accept\n"
"    (context, messages, private_data) arguments and return a sequence\n"
"    of responses. See pam_conv(3).\n"
"conversation_private_data : object, optional\n"
"    Private data passed to the conversation function (default=None)\n"
"confdir : str, optional\n"
"    Path to directory containing PAM configuration files (default=None\n"
"    for /etc/pam.d). See pam_start_confdir(3).\n"
"rhost : str, optional\n"
"    Remote hostname (stored as PAM_RHOST item, default=None).\n"
"    See pam_set_item(3).\n"
"ruser : str, optional\n"
"    Remote username (stored as PAM_RUSER item, default=None).\n"
"    See pam_set_item(3).\n"
"fail_delay : int, optional\n"
"    Delay in microseconds on authentication failure (default=0).\n"
"    Note that PAM modules may enforce their own default fail delay\n"
"    regardless of this setting. See pam_fail_delay(3).\n\n"
"Returns\n"
"-------\n"
"PamContext\n"
"    A new PAM context object for performing authentication and session\n"
"    operations\n\n"
"Raises\n"
"------\n"
"PAMError\n"
"    If PAM initialization fails or invalid parameters are provided\n"
"ValueError\n"
"    If required parameters are missing or conversation_function is not\n"
"    callable\n"
"TypeError\n"
"    If parameters are not of the expected types\n"
);

static PyObject *tnpam_get_context(PyObject *self, PyObject *args, PyObject *kwds)
{
	return PyObject_Call((PyObject *)&PyPamCtx_Type, args, kwds);
}

static PyMethodDef tnpam_methods[] = {
	{
		.ml_name = "get_context",
		.ml_meth = (PyCFunction)tnpam_get_context,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = tnpam_get_context__doc__
	},
	{NULL, NULL, 0, NULL}
};

static int
tnpam_module_clear(PyObject *m)
{
	tnpam_state_t *state = (tnpam_state_t *)PyModule_GetState(m);
	Py_CLEAR(state->pam_error);
	Py_CLEAR(state->pam_code_enum);
	Py_CLEAR(state->msg_style_enum);
	Py_CLEAR(state->struct_pam_msg_type);
	Py_CLEAR(state->cred_op_enum);
	return 0;
}

static int
tnpam_module_traverse(PyObject *m, visitproc visit, void *arg)
{
	tnpam_state_t *state = (tnpam_state_t *)PyModule_GetState(m);
	Py_VISIT(state->pam_error);
	Py_VISIT(state->pam_code_enum);
	Py_VISIT(state->msg_style_enum);
	Py_VISIT(state->struct_pam_msg_type);
	Py_VISIT(state->cred_op_enum);
	return 0;
}

static void
tnpam_module_free(void *m)
{
	tnpam_module_clear((PyObject *)m);
}

PyDoc_STRVAR(truenas_pypam_module__doc__,
"TrueNAS PAM client library for user authentication and session management.\n\n"
"This module provides Python bindings for the PAM (Pluggable Authentication\n"
"Modules) library, allowing applications to perform user authentication,\n"
"session management, and environment variable operations through PAM.\n\n"
"Key Features:\n"
"- Thread-safe PAM operations with proper GIL management\n"
"- Conversation callback support for interactive authentication\n"
"- PAM environment variable management\n"
"- Comprehensive error handling with PAM-specific exceptions\n\n"
"Main Functions:\n"
"- get_context(): Create a new PAM context for authentication\n\n"
"Main Classes:\n"
"- PamContext: PAM context object with authentication methods\n"
"- PAMError: Exception class for PAM-related errors\n"
);

PyModuleDef truenas_pypam_module = {
	PyModuleDef_HEAD_INIT,
	.m_name = MODULE_NAME,
	.m_doc = truenas_pypam_module__doc__,
	.m_size = sizeof(tnpam_state_t),
	.m_methods = tnpam_methods,
	.m_clear = tnpam_module_clear,
	.m_free = tnpam_module_free,
	.m_traverse = tnpam_module_traverse,
};

// Generic function to get module state. NULL for module_in is OK
tnpam_state_t *py_get_pam_state(PyObject *module_in)
{
	PyObject *modref = module_in;
	tnpam_state_t *state = NULL;

	if (modref == NULL) {
		// this is a borrowed referece. does not need decref
		modref = PyState_FindModule(&truenas_pypam_module);
		PYPAM_ASSERT((modref != NULL), "Failed to get module");
	}

	state = (tnpam_state_t *)PyModule_GetState(modref);
	PYPAM_ASSERT((state != NULL), "Failed to get module state");
	return state;
}

PyMODINIT_FUNC
PyInit_truenas_pypam(void)
{
	PyObject *mod = NULL;

	if (PyType_Ready(&PyPamCtx_Type) < 0) {
		return NULL;
	}

	mod = PyModule_Create(&truenas_pypam_module);
	if (mod == NULL) {
		return NULL;
	}

	/* Create PamError exception */
	if (!setup_pam_exception(mod)) {
		Py_DECREF(mod);
		return NULL;
	}

	/* Set up our pam conversation py structs */
	if (!init_pam_conv_struct(mod)) {
		Py_DECREF(mod);
		return NULL;
	}

	/* Set up CredOp enum */
	if (!setup_cred_op_enum(mod)) {
		Py_DECREF(mod);
		return NULL;
	}

	return mod;
}
