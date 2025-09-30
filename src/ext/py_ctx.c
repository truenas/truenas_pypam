// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pypam.h"

typedef struct {
	const char *service;
	const char *user;
	const char *cdir;
	PyObject *conv_fn;
	PyObject *private_data;
	const char *ruser;
	const char *rhost;
	uint32_t fail_delay;
} tnpam_cfg_t;

static int
py_tnpam_ctx_init(tnpam_ctx_t *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"service_name",
		"user",
		"conversation_function",
		"conversation_private_data",
		"confdir",
		"rhost",
		"ruser",
		"fail_delay",
		NULL
	};
	tnpam_cfg_t cfg = { .service = "login", };
	pamcode_t ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$ssOOsssI", kwlist,
					 &cfg.service,
					 &cfg.user,
					 &cfg.conv_fn,
					 &cfg.private_data,
					 &cfg.cdir,
					 &cfg.rhost,
					 &cfg.ruser,
					 &cfg.fail_delay)) {
		return -1;
	}

	if (cfg.user == NULL) {
		PyErr_SetString(PyExc_ValueError, "user is required");
		return -1;
	}

	if (cfg.conv_fn == NULL) {
		PyErr_SetString(PyExc_ValueError, "conversation_function is required");
		return -1;
	}

	if (!PyCallable_Check(cfg.conv_fn)) {
		PyErr_SetString(PyExc_TypeError, "conversation_function must be callable");
		return -1;
	}

	self->conv.conv = truenas_pam_conv;
	self->conv.appdata_ptr = (void *)self;  // Use borrowed reference
	self->conv_data.callback_fn = Py_NewRef(cfg.conv_fn);
	self->conv_data.private_data = cfg.private_data ?
				       Py_NewRef(cfg.private_data) :
				       Py_NewRef(Py_None);
	self->conv_data.messages = PyList_New(0);
	if (self->conv_data.messages == NULL) {
		return -1;
	}

	ret = pam_start_confdir(cfg.service, cfg.user, &self->conv,
				cfg.cdir, &self->hdl);
	if (ret != PAM_SUCCESS) {
		set_pam_exc(ret, "pam_start_confdir() failed");
		return -1;
	}

	// Store username for audit logging
	self->user = PyUnicode_FromString(cfg.user);
	if (self->user == NULL) {
		return -1;
	}

	// Initialize last_pam_result to PAM_SUCCESS
	self->last_pam_result = PAM_SUCCESS;

	ret = pam_set_item(self->hdl, PAM_RUSER, cfg.ruser);
	if (ret != PAM_SUCCESS) {
		set_pam_exc(ret, "pam_set_item() failed for PAM_RUSER");
		return -1;
	}

	ret = pam_set_item(self->hdl, PAM_RHOST, cfg.rhost);
	if (ret != PAM_SUCCESS) {
		set_pam_exc(ret, "pam_set_item() failed for PAM_RHOST");
		return -1;
	}

	if (cfg.fail_delay) {
		ret = pam_fail_delay(self->hdl, cfg.fail_delay);
		if (ret != PAM_SUCCESS) {
			set_pam_exc(ret, "pam_fail_delay() failed");
			return -1;
		}
	}

	return 0;
}

static void
py_tnpam_ctx_dealloc(tnpam_ctx_t *self)
{
	if (self->hdl != NULL) {
		pam_end(self->hdl, self->last_pam_result);
		self->hdl = NULL;
	}
	Py_CLEAR(self->user);
	Py_CLEAR(self->conv_data.callback_fn);
	Py_CLEAR(self->conv_data.private_data);
	Py_CLEAR(self->conv_data.messages);
	// conv.appdata_ptr is a borrowed reference, no need to clear

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyMethodDef py_tnpam_ctx_methods[] = {
	{
		.ml_name = "authenticate",
		.ml_meth = (PyCFunction)py_tnpam_authenticate,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnpam_authenticate__doc__,
	},
	{
		.ml_name = "acct_mgmt",
		.ml_meth = (PyCFunction)py_tnpam_acct_mgmt,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnpam_acct_mgmt__doc__,
	},
	{
		.ml_name = "chauthtok",
		.ml_meth = (PyCFunction)py_tnpam_chauthtok,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnpam_chauthtok__doc__,
	},
	{
		.ml_name = "get_env",
		.ml_meth = (PyCFunction)py_tnpam_getenv,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnpam_getenv__doc__,
	},
	{
		.ml_name = "set_env",
		.ml_meth = (PyCFunction)py_tnpam_setenv,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnpam_setenv__doc__,
	},
	{
		.ml_name = "env_dict",
		.ml_meth = (PyCFunction)py_tnpam_envlist,
		.ml_flags = METH_NOARGS,
		.ml_doc = py_tnpam_envlist__doc__,
	},
	{
		.ml_name = "setcred",
		.ml_meth = (PyCFunction)py_tnpam_setcred,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnpam_setcred__doc__,
	},
	{
		.ml_name = "open_session",
		.ml_meth = (PyCFunction)py_tnpam_open_session,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnpam_open_session__doc__,
	},
	{
		.ml_name = "close_session",
		.ml_meth = (PyCFunction)py_tnpam_close_session,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnpam_close_session__doc__,
	},
	{NULL}
};

PyDoc_STRVAR(PyPamCtx_Type__doc__,
"PamContext(service_name='login', *, user, conversation_function,\n"
"           conversation_private_data=None, confdir=None, rhost=None,\n"
"           ruser=None, fail_delay=0)\n"
"----------------------------------------------------------------\n\n"
"PAM context object for user authentication and session management.\n\n"
"This object wraps a PAM handle (pam_handle_t) and provides methods for\n"
"performing PAM operations such as authentication and environment variable\n"
"management. The context automatically manages the PAM handle lifecycle.\n\n"
"The context maintains thread safety by using mutex locks around PAM\n"
"operations, as PAM handles are not thread-safe. It also manages the\n"
"Python GIL properly during PAM conversation callbacks.\n\n"
"Parameters are the same as get_context(). See get_context() for\n"
"detailed parameter documentation.\n"
);

PyTypeObject PyPamCtx_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = MODULE_NAME ".PamContext",
	.tp_doc = PyPamCtx_Type__doc__,
	.tp_basicsize = sizeof(tnpam_ctx_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_init = (initproc)py_tnpam_ctx_init,
	.tp_dealloc = (destructor)py_tnpam_ctx_dealloc,
	//.tp_repr = (reprfunc)py_tnpam_ctx_repr,
	.tp_methods = py_tnpam_ctx_methods,
	//.tp_getset = py_tnpam_ctx_getsetters,
};
