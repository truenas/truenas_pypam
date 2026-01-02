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
	pamcode_t ret, err = 0;
	const char *msg = NULL;

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

	// truenas_pam_conv is the hard-coded C callback function that wraps around the
	// provided python callback function in self->conv_data.callback_fn.
	self->conv.conv = truenas_pam_conv;

	// the appdata_ptr provided to pam_start() is actually a borrowed reference to
	// the current object. This provides access to handle python state, mutex, etc
	// within truenas_pam_conv and also allows the *user-provided* private_data to
	// the user-provided callback function
	self->conv.appdata_ptr = (void *)self;  // Use borrowed reference
	self->conv_data.callback_fn = Py_NewRef(cfg.conv_fn);
	self->conv_data.private_data = cfg.private_data ?
				       Py_NewRef(cfg.private_data) :
				       Py_NewRef(Py_None);

	// history of messages received from PAM service modules.
	self->conv_data.messages = PyList_New(0);
	if (self->conv_data.messages == NULL) {
		goto cleanup;
	}

	Py_BEGIN_ALLOW_THREADS
	ret = pam_start_confdir(cfg.service, cfg.user, &self->conv,
				cfg.cdir, &self->hdl);

	if (ret != PAM_SUCCESS) {
		msg = "pam_start_confdir() failed";
	} else if ((ret = pam_set_item(self->hdl, PAM_RUSER, cfg.ruser)) != PAM_SUCCESS) {
		msg = "pam_set_item() failed for PAM_RUSER";
	} else if ((ret = pam_set_item(self->hdl, PAM_RHOST, cfg.rhost)) != PAM_SUCCESS) {
		msg = "pam_set_item() failed for PAM_HOST";
	} else if (cfg.fail_delay &&
		   ((ret = pam_fail_delay(self->hdl, cfg.fail_delay) != PAM_SUCCESS))) {
		msg = "pam_fail_delay() failed";
	} else {
		err = pthread_mutex_init(&self->pam_hdl_lock, NULL);
	}
	Py_END_ALLOW_THREADS

	if (ret != PAM_SUCCESS) {
		set_pam_exc(ret, msg);
		goto cleanup;
	}

	if (err) {
		PyErr_Format(PyExc_RuntimeError,
			     "pthread_muex_init() failed for pam_hdl_lock: %s",
			     strerror(errno));
		goto cleanup;
	}

	// Store username for audit logging
	self->user = PyUnicode_FromString(cfg.user);
	if (self->user == NULL) {
		goto cleanup_mutex;
	}

	// Initialize last_pam_result to PAM_SUCCESS
	self->last_pam_result = PAM_SUCCESS;

	// Initialize _save to NULL - it will be set by PYPAM_LOCK on first use
	self->_save = NULL;

	return 0;

cleanup_mutex:
	pthread_mutex_destroy(&self->pam_hdl_lock);
cleanup:
	if (self->hdl != NULL) {
		pam_end(self->hdl, PAM_ABORT);
		self->hdl = NULL;
	}
	Py_CLEAR(self->conv_data.callback_fn);
	Py_CLEAR(self->conv_data.private_data);
	Py_CLEAR(self->conv_data.messages);
	return -1;
}

static void
py_tnpam_ctx_dealloc(tnpam_ctx_t *self)
{
	if (self->hdl != NULL) {
		pam_end(self->hdl, self->last_pam_result);
		self->hdl = NULL;
	}
	pthread_mutex_destroy(&self->pam_hdl_lock);
	Py_CLEAR(self->user);
	Py_CLEAR(self->conv_data.callback_fn);
	Py_CLEAR(self->conv_data.private_data);
	Py_CLEAR(self->conv_data.messages);
	// conv.appdata_ptr is a borrowed reference, no need to clear

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static
PyObject *py_tnpam_ctx_messages(tnpam_ctx_t *self, PyObject *Py_UNUSED(ignored))
{
	return PyList_AsTuple(self->conv_data.messages);
}

/* Getters and setters for PAM items */

PyDoc_STRVAR(py_tnpam_ctx_user__doc__,
"str or None: The PAM username (PAM_USER).\n\n"
"This attribute corresponds to the PAM_USER item and represents the\n"
"username of the entity being authenticated. The value is retrieved\n"
"from the underlying PAM handle via pam_get_item(3).\n\n"
"When setting this attribute, the value is updated in the PAM handle\n"
"via pam_set_item(3).\n\n"
"Raises\n"
"------\n"
"TypeError\n"
"    If the value is not a string when setting.\n"
"PAMError\n"
"    If pam_set_item(3) or pam_get_item(3) fails.\n"
);

PyDoc_STRVAR(py_tnpam_ctx_ruser__doc__,
"str or None: The PAM remote username (PAM_RUSER).\n\n"
"This attribute corresponds to the PAM_RUSER item and represents the\n"
"name of the remote user who is requesting service. This is typically\n"
"used for services like rlogin where a user on one system requests\n"
"access to another system. The value is retrieved from the underlying\n"
"PAM handle via pam_get_item(3).\n\n"
"When setting this attribute, the value is updated in the PAM handle\n"
"via pam_set_item(3).\n\n"
"Raises\n"
"------\n"
"TypeError\n"
"    If the value is not a string when setting.\n"
"PAMError\n"
"    If pam_set_item(3) or pam_get_item(3) fails.\n"
);

PyDoc_STRVAR(py_tnpam_ctx_rhost__doc__,
"str or None: The PAM remote host (PAM_RHOST).\n\n"
"This attribute corresponds to the PAM_RHOST item and represents the\n"
"name or address of the remote host from which the service request is\n"
"originating. This can be a hostname, IPv4 address, or IPv6 address.\n"
"The value is retrieved from the underlying PAM handle via\n"
"pam_get_item(3).\n\n"
"When setting this attribute, the value is updated in the PAM handle\n"
"via pam_set_item(3).\n\n"
"Raises\n"
"------\n"
"TypeError\n"
"    If the value is not a string when setting.\n"
"PAMError\n"
"    If pam_set_item(3) or pam_get_item(3) fails.\n"
);

static PyObject *
py_tnpam_ctx_get_user(tnpam_ctx_t *self, void *closure)
{
	const void *item = NULL;
	pamcode_t ret;

	PYPAM_LOCK(self);
	ret = pam_get_item(self->hdl, PAM_USER, &item);
	PYPAM_UNLOCK(self);

	if (ret != PAM_SUCCESS) {
		set_pam_exc(ret, "pam_get_item() failed for PAM_USER");
		return NULL;
	}

	if (item == NULL) {
		Py_RETURN_NONE;
	}

	return PyUnicode_FromString((const char *)item);
}

static int
py_tnpam_ctx_set_user(tnpam_ctx_t *self, PyObject *value, void *closure)
{
	pamcode_t ret;
	const char *str;

	if (value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete user attribute");
		return -1;
	}

	if (!PyUnicode_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "user must be a string");
		return -1;
	}

	str = PyUnicode_AsUTF8(value);
	if (str == NULL) {
		return -1;
	}

	PYPAM_LOCK(self);
	ret = pam_set_item(self->hdl, PAM_USER, str);
	PYPAM_UNLOCK(self);

	if (ret != PAM_SUCCESS) {
		set_pam_exc(ret, "pam_set_item() failed for PAM_USER");
		return -1;
	}

	return 0;
}

static PyObject *
py_tnpam_ctx_get_ruser(tnpam_ctx_t *self, void *closure)
{
	const void *item = NULL;
	pamcode_t ret;

	PYPAM_LOCK(self);
	ret = pam_get_item(self->hdl, PAM_RUSER, &item);
	PYPAM_UNLOCK(self);

	if (ret != PAM_SUCCESS) {
		set_pam_exc(ret, "pam_get_item() failed for PAM_RUSER");
		return NULL;
	}

	if (item == NULL) {
		Py_RETURN_NONE;
	}

	return PyUnicode_FromString((const char *)item);
}

static int
py_tnpam_ctx_set_ruser(tnpam_ctx_t *self, PyObject *value, void *closure)
{
	pamcode_t ret;
	const char *str;

	if (value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete ruser attribute");
		return -1;
	}

	if (!PyUnicode_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "ruser must be a string");
		return -1;
	}

	str = PyUnicode_AsUTF8(value);
	if (str == NULL) {
		return -1;
	}

	PYPAM_LOCK(self);
	ret = pam_set_item(self->hdl, PAM_RUSER, str);
	PYPAM_UNLOCK(self);

	if (ret != PAM_SUCCESS) {
		set_pam_exc(ret, "pam_set_item() failed for PAM_RUSER");
		return -1;
	}

	return 0;
}

static PyObject *
py_tnpam_ctx_get_rhost(tnpam_ctx_t *self, void *closure)
{
	const void *item = NULL;
	pamcode_t ret;

	PYPAM_LOCK(self);
	ret = pam_get_item(self->hdl, PAM_RHOST, &item);
	PYPAM_UNLOCK(self);

	if (ret != PAM_SUCCESS) {
		set_pam_exc(ret, "pam_get_item() failed for PAM_RHOST");
		return NULL;
	}

	if (item == NULL) {
		Py_RETURN_NONE;
	}

	return PyUnicode_FromString((const char *)item);
}

static int
py_tnpam_ctx_set_rhost(tnpam_ctx_t *self, PyObject *value, void *closure)
{
	pamcode_t ret;
	const char *str;

	if (value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete rhost attribute");
		return -1;
	}

	if (!PyUnicode_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "rhost must be a string");
		return -1;
	}

	str = PyUnicode_AsUTF8(value);
	if (str == NULL) {
		return -1;
	}

	PYPAM_LOCK(self);
	ret = pam_set_item(self->hdl, PAM_RHOST, str);
	PYPAM_UNLOCK(self);

	if (ret != PAM_SUCCESS) {
		set_pam_exc(ret, "pam_set_item() failed for PAM_RHOST");
		return -1;
	}

	return 0;
}

PyDoc_STRVAR(py_tnpam_set_conversation__doc__,
"set_conversation(*, conversation_function) -> None\n"
"---------------------------------------------------\n\n"
"Replace the conversation function.\n\n"
"This method allows updating the conversation callback function after the\n"
"PAM context has been created. This can be useful when the conversation\n"
"handling needs to change during the lifecycle of the PAM session.\n\n"
"Parameters\n"
"----------\n"
"conversation_function : callable\n"
"    New callback function for PAM conversation. Must accept three arguments:\n"
"    (ctx, messages, private_data) where ctx is the PAM context, messages is\n"
"    a tuple of struct_pam_message objects, and private_data is the private\n"
"    data provided when the context was created.\n\n"
"Raises\n"
"------\n"
"ValueError\n"
"    If conversation_function is not provided\n"
"TypeError\n"
"    If conversation_function is not callable\n\n"
"Note\n"
"----\n"
"The old conversation function reference is released when this method is called.\n"
"The private data remains unchanged.\n"
);
static PyObject *
py_tnpam_set_conversation(tnpam_ctx_t *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"conversation_function",
		NULL
	};
	PyObject *conv_fn = NULL;
	PyObject *old_conv_fn = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$O", kwlist,
					 &conv_fn)) {
		return NULL;
	}

	if (conv_fn == NULL) {
		PyErr_SetString(PyExc_ValueError, "conversation_function is required");
		return NULL;
	}

	if (!PyCallable_Check(conv_fn)) {
		PyErr_SetString(PyExc_TypeError, "conversation_function must be callable");
		return NULL;
	}

	// Save old reference
	old_conv_fn = self->conv_data.callback_fn;

	// Set new reference
	self->conv_data.callback_fn = Py_NewRef(conv_fn);

	// Release old reference
	Py_XDECREF(old_conv_fn);

	Py_RETURN_NONE;
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
	{
		.ml_name = "messages",
		.ml_meth = (PyCFunction)py_tnpam_ctx_messages,
		.ml_flags = METH_NOARGS,
	},
	{
		.ml_name = "set_conversation",
		.ml_meth = (PyCFunction)py_tnpam_set_conversation,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnpam_set_conversation__doc__,
	},
	{NULL}
};

static PyGetSetDef py_tnpam_ctx_getsetters[] = {
	{
		.name = "user",
		.get = (getter)py_tnpam_ctx_get_user,
		.set = (setter)py_tnpam_ctx_set_user,
		.doc = py_tnpam_ctx_user__doc__,
		.closure = NULL,
	},
	{
		.name = "ruser",
		.get = (getter)py_tnpam_ctx_get_ruser,
		.set = (setter)py_tnpam_ctx_set_ruser,
		.doc = py_tnpam_ctx_ruser__doc__,
		.closure = NULL,
	},
	{
		.name = "rhost",
		.get = (getter)py_tnpam_ctx_get_rhost,
		.set = (setter)py_tnpam_ctx_set_rhost,
		.doc = py_tnpam_ctx_rhost__doc__,
		.closure = NULL,
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
	.tp_getset = py_tnpam_ctx_getsetters,
};
