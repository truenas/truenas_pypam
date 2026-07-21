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
	int fail_delay;
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

	/*
	 * __init__ is an ordinary method and nothing in CPython stops a caller
	 * invoking it twice (Objects/typeobject.c wrap_init()). A second pass
	 * would overwrite self->hdl without pam_end()ing the first handle,
	 * overwrite the Python references without releasing them, and re-run
	 * pthread_*_init on live primitives -- possibly underneath a parked auth
	 * thread. tp_alloc() zeroes the struct, so a NULL handle means
	 * uninitialized.
	 */
	if (self->hdl != NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"PamContext is already initialized");
		return -1;
	}

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$ssOOsssi", kwlist,
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

	/*
	 * Parsed with "i", not "I": "I" masks out-of-range values via
	 * PyLong_AsUnsignedLongMask() instead of raising.
	 */
	if (cfg.fail_delay < 0) {
		PyErr_SetString(PyExc_ValueError, "fail_delay must not be negative");
		return -1;
	}

	if (cfg.conv_fn != NULL) {
		if (!PyCallable_Check(cfg.conv_fn)) {
			PyErr_SetString(PyExc_TypeError, "conversation_function must be callable");
			return -1;
		}

		// truenas_pam_conv is the hard-coded C callback function that wraps around
		// the provided python callback function in self->conv_data.callback_fn.
		self->conv.conv = truenas_pam_conv;

		// appdata_ptr is a borrowed reference to the current object.
		self->conv.appdata_ptr = (void *)self;
		self->conv_data.py_cb.callback_fn = Py_NewRef(cfg.conv_fn);
		self->conv_data.py_cb.private_data = cfg.private_data ?
						        Py_NewRef(cfg.private_data) :
						        Py_NewRef(Py_None);

		// history of messages received from PAM service modules.
		self->conv_data.py_cb.messages = PyList_New(0);
		if (self->conv_data.py_cb.messages == NULL) {
			goto cleanup;
		}
	} else {
		// Internal thread mode: use tnpam_internal_conv instead of a Python callback.
		self->conv_type = TNPAM_CONV_INTERNAL_THREAD;
		self->conv.conv = tnpam_internal_conv;
		self->conv.appdata_ptr = (void *)self;
		self->conv_data.th_cb.messages = PyList_New(0);
		if (self->conv_data.th_cb.messages == NULL) {
			goto cleanup;
		}
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
	} else if (self->conv_type == TNPAM_CONV_INTERNAL_THREAD) {
		/*
		 * pam_hdl_lock is a PyMutex: zero-initialized by tp_alloc().
		 *
		 * The condition variables are given a CLOCK_MONOTONIC attribute
		 * so their absolute deadlines are immune to wall-clock steps. A
		 * default-attribute condvar waits on CLOCK_REALTIME, where an
		 * NTP correction mid-login either expires the deadline
		 * immediately (spurious TimeoutError on a login the user
		 * answered promptly) or pushes it hours into the future,
		 * silently disabling the timeout.
		 */
		pthread_condattr_t cattr;

		err = pthread_condattr_init(&cattr);
		if (!err) {
			err = pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
			if (!err) err = pthread_mutex_init(&self->conv_data.th_cb.conv_mutex, NULL);
			if (!err) err = pthread_cond_init(&self->conv_data.th_cb.conv_cond_main, &cattr);
			if (!err) err = pthread_cond_init(&self->conv_data.th_cb.conv_cond_auth, &cattr);
			pthread_condattr_destroy(&cattr);
		}
		if (!err) {
			self->conv_data.th_cb.sync_ready = B_TRUE;
		}
	}
	Py_END_ALLOW_THREADS

	if (ret != PAM_SUCCESS) {
		set_pam_exc(ret, msg);
		goto cleanup;
	}

	if (err) {
		PyErr_Format(PyExc_RuntimeError,
			     "pthread mutex/cond init failed: %s",
			     strerror(err));
		goto cleanup;
	}

	// Store username for audit logging
	self->user = PyUnicode_FromString(cfg.user);
	if (self->user == NULL) {
		goto cleanup;
	}

	// Initialize last_pam_result to PAM_SUCCESS
	self->last_pam_result = PAM_SUCCESS;

	// Initialize _save to NULL - it will be set by PYPAM_LOCK on first use
	self->_save = NULL;

	return 0;

cleanup:
	if (self->hdl != NULL) {
		pam_end(self->hdl, PAM_ABORT);
		self->hdl = NULL;
	}
	if (self->conv_type == TNPAM_CONV_CALLBACK) {
		Py_CLEAR(self->conv_data.py_cb.callback_fn);
		Py_CLEAR(self->conv_data.py_cb.private_data);
		Py_CLEAR(self->conv_data.py_cb.messages);
	} else {
		Py_CLEAR(self->conv_data.th_cb.messages);
	}
	return -1;
}

/*
 * The context holds strong references to caller-supplied objects (the
 * conversation callback and its private data), making it a container type that
 * must participate in cycle collection. An object that owns a context and hands
 * it a bound method forms a cycle through it; a context the collector cannot
 * traverse is never deallocated, so pam_end() and the modules' cleanup handlers
 * never run, at shutdown included.
 *
 * conv_data is a union: both callbacks must switch on conv_type, or the
 * collector is handed a pointer read out of the wrong struct layout.
 */
static int
py_tnpam_ctx_traverse(tnpam_ctx_t *self, visitproc visit, void *arg)
{
	Py_VISIT(self->user);

	if (self->conv_type == TNPAM_CONV_CALLBACK) {
		Py_VISIT(self->conv_data.py_cb.callback_fn);
		Py_VISIT(self->conv_data.py_cb.private_data);
		Py_VISIT(self->conv_data.py_cb.messages);
	} else {
		Py_VISIT(self->conv_data.th_cb.messages);
	}

	return 0;
}

static int
py_tnpam_ctx_clear(tnpam_ctx_t *self)
{
	Py_CLEAR(self->user);

	if (self->conv_type == TNPAM_CONV_CALLBACK) {
		Py_CLEAR(self->conv_data.py_cb.callback_fn);
		Py_CLEAR(self->conv_data.py_cb.private_data);
		Py_CLEAR(self->conv_data.py_cb.messages);
	} else {
		Py_CLEAR(self->conv_data.th_cb.messages);
	}

	return 0;
}

static void
py_tnpam_ctx_dealloc(tnpam_ctx_t *self)
{
	PyObject_GC_UnTrack(self);

	if (self->conv_type == TNPAM_CONV_INTERNAL_THREAD) {
		tnpam_thread_conv_t *th = &self->conv_data.th_cb;

		if (th->thread_started && !th->thread_joined) {
			/*
			 * Cancel and join without the GIL. pam_authenticate()
			 * does not return until the module unwinds, and a
			 * module's registered fail delay is slept inside it
			 * (pam_unix registers two seconds, see
			 * modules/pam_unix/support.c and libpam/pam_delay.c),
			 * so holding the GIL here freezes every Python thread
			 * in the process -- indefinitely against a module
			 * wedged in network I/O.
			 */
			Py_BEGIN_ALLOW_THREADS
			pthread_mutex_lock(&th->conv_mutex);
			th->conv_state = THREAD_STATE_CONV_CANCELLED;
			pthread_cond_signal(&th->conv_cond_auth);
			pthread_mutex_unlock(&th->conv_mutex);
			pthread_join(th->auth_thread, NULL);
			Py_END_ALLOW_THREADS
			th->thread_joined = B_TRUE;

			/*
			 * pam_end() is contractually given the result of the
			 * last PAM call. Modules receive that status in their
			 * cleanup handlers and some persist state only when it
			 * says the transaction succeeded, so reporting the
			 * default PAM_SUCCESS for an abandoned authentication
			 * makes a failed login look like a completed one.
			 */
			self->last_pam_result = th->auth_result;
		}

		/*
		 * Responses continue_authentication() handed over that the
		 * conversation never consumed -- they hold the user's plaintext
		 * password.
		 */
		free_pam_resp(th->num_pending_msgs, th->pending_resps);
		th->pending_resps = NULL;

		if (th->sync_ready) {
			pthread_cond_destroy(&th->conv_cond_auth);
			pthread_cond_destroy(&th->conv_cond_main);
			pthread_mutex_destroy(&th->conv_mutex);
		}
	}

	if (self->hdl != NULL) {
		pam_end(self->hdl, self->last_pam_result);
		self->hdl = NULL;
	}

	/* conv.appdata_ptr is a borrowed reference, no need to clear */
	py_tnpam_ctx_clear(self);

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static
PyObject *py_tnpam_ctx_messages(tnpam_ctx_t *self, PyObject *Py_UNUSED(ignored))
{
	if (self->conv_type == TNPAM_CONV_CALLBACK) {
		return PyList_AsTuple(self->conv_data.py_cb.messages);
	}
	return PyList_AsTuple(self->conv_data.th_cb.messages);
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

	/*
	 * open_session() and setcred() gate only on the authenticated flag and
	 * never re-check who authenticated, so repointing PAM_USER afterwards
	 * would establish a session and credentials for a principal that never
	 * authenticated. Nothing needs to rename a context mid-transaction, so
	 * refuse rather than try to keep the two in step.
	 */
	if (self->authenticated) {
		PyErr_SetString(PyExc_RuntimeError,
				"user cannot be changed after authentication");
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

	if (self->conv_type != TNPAM_CONV_CALLBACK) {
		PyErr_SetString(PyExc_RuntimeError,
				"set_conversation() is only available on contexts "
				"created with a conversation_function");
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
	old_conv_fn = self->conv_data.py_cb.callback_fn;

	// Set new reference
	self->conv_data.py_cb.callback_fn = Py_NewRef(conv_fn);

	// Release old reference
	Py_XDECREF(old_conv_fn);

	Py_RETURN_NONE;
}

PyDoc_STRVAR(py_tnpam_begin_authentication__doc__,
"begin_authentication(*, silent=False, disallow_null_authtok=False, timeout=None)\n"
"---------------------------------------------------------------------------------\n\n"
"Start PAM authentication on an internal C thread.\n\n"
"Only valid for contexts created without a conversation_function. Launches\n"
"pam_authenticate(3) on a background pthread and returns when PAM either\n"
"needs user input or completes.\n\n"
"Parameters\n"
"----------\n"
"silent : bool, optional\n"
"    Do not emit any messages during authentication (default=False).\n"
"disallow_null_authtok : bool, optional\n"
"    Return PAM_AUTH_ERR if the user has no authentication token (default=False).\n"
"timeout : float or None, optional\n"
"    Maximum seconds to wait for the first conversation or completion.\n"
"    0 means wait indefinitely (default=0). Maximum is 300.\n\n"
"    The timeout bounds the wait for the PAM stack to reach its next\n"
"    conversation or finish; it does not bound an unresponsive module. A\n"
"    module cannot be aborted mid-call without leaving the PAM handle and\n"
"    the module's own state inconsistent, so cancellation only takes effect\n"
"    once the module next returns. If one is wedged in I/O -- an\n"
"    unreachable directory server, say -- TimeoutError is raised only when\n"
"    it finally returns.\n"
"Returns\n"
"-------\n"
"tuple of struct_pam_message\n"
"    When PAM needs user input (echo-off prompt, echo-on prompt, etc.).\n"
"None\n"
"    When authentication succeeds without requiring further input.\n\n"
"Raises\n"
"------\n"
"PAMError\n"
"    Authentication failed.\n"
"TimeoutError\n"
"    The timeout was exceeded.\n"
"RuntimeError\n"
"    Called on a context that has a conversation_function, or authentication\n"
"    is already in progress.\n"
);

PyDoc_STRVAR(py_tnpam_continue_authentication__doc__,
"continue_authentication(responses, *, timeout=None)\n"
"-----------------------------------------------------\n\n"
"Send responses to a pending PAM conversation and wait for the next step.\n\n"
"Must be called after begin_authentication() or a previous call to this\n"
"method returned a messages tuple.\n\n"
"Parameters\n"
"----------\n"
"responses : iterable of str or None\n"
"    One response per pending message, in order. Use None for messages\n"
"    that do not require a reply (PAM_TEXT_INFO, PAM_ERROR_MSG).\n"
"timeout : float or None, optional\n"
"    Maximum seconds to wait for the next conversation or completion.\n"
"    None means wait indefinitely (default=None).\n\n"
"Returns\n"
"-------\n"
"tuple of struct_pam_message\n"
"    When PAM needs further input.\n"
"None\n"
"    When authentication completes successfully.\n\n"
"Raises\n"
"------\n"
"PAMError\n"
"    Authentication failed.\n"
"TimeoutError\n"
"    The timeout was exceeded.\n"
"RuntimeError\n"
"    No conversation is currently pending.\n"
);

static PyMethodDef py_tnpam_ctx_methods[] = {
	{
		.ml_name = "authenticate",
		.ml_meth = (PyCFunction)py_tnpam_authenticate,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnpam_authenticate__doc__,
	},
	{
		.ml_name = "begin_authentication",
		.ml_meth = (PyCFunction)py_tnpam_begin_authentication,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnpam_begin_authentication__doc__,
	},
	{
		.ml_name = "continue_authentication",
		.ml_meth = (PyCFunction)py_tnpam_continue_authentication,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = py_tnpam_continue_authentication__doc__,
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
"A PAM handle is not thread-safe and a context must be driven by one\n"
"thread at a time; use a separate context per concurrent authentication.\n"
"A mutex serializes calls into libpam so that concurrent access cannot\n"
"corrupt the handle -- including against the internal thread that runs\n"
"pam_authenticate() for begin_authentication() -- but it does not make a\n"
"context safe to share. The context also manages the Python GIL properly\n"
"during PAM conversation callbacks.\n\n"
"Parameters are the same as get_context(). See get_context() for\n"
"detailed parameter documentation.\n"
);

PyTypeObject PyPamCtx_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = MODULE_NAME ".PamContext",
	.tp_doc = PyPamCtx_Type__doc__,
	.tp_basicsize = sizeof(tnpam_ctx_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_new = PyType_GenericNew,
	.tp_init = (initproc)py_tnpam_ctx_init,
	.tp_dealloc = (destructor)py_tnpam_ctx_dealloc,
	.tp_traverse = (traverseproc)py_tnpam_ctx_traverse,
	.tp_clear = (inquiry)py_tnpam_ctx_clear,
	//.tp_repr = (reprfunc)py_tnpam_ctx_repr,
	.tp_methods = py_tnpam_ctx_methods,
	.tp_getset = py_tnpam_ctx_getsetters,
};
