// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pypam.h"

typedef struct {
	const char *name;
	int value;
} msg_style_entry_t;

static const msg_style_entry_t msg_style_tbl[] = {
	{"PAM_PROMPT_ECHO_OFF", PAM_PROMPT_ECHO_OFF},
	{"PAM_PROMPT_ECHO_ON", PAM_PROMPT_ECHO_ON},
	{"PAM_ERROR_MSG", PAM_ERROR_MSG},
	{"PAM_TEXT_INFO", PAM_TEXT_INFO}
};

static PyObject *
create_msg_style_enum(void)
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

	for (i = 0; i < ARRAY_SIZE(msg_style_tbl); i++) {
		PyObject *py_value = PyLong_FromLong(msg_style_tbl[i].value);
		if (py_value == NULL ||
		    PyDict_SetItemString(enum_dict, msg_style_tbl[i].name,
					 py_value) < 0) {
			Py_XDECREF(py_value);
			Py_DECREF(enum_dict);
			Py_DECREF(int_enum_class);
			return NULL;
		}
		Py_DECREF(py_value);
	}

	py_enum_name = PyUnicode_FromString(MODULE_NAME ".MSGStyle");
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

PyStructSequence_Field struct_pam_msg [] = {
	{"msg_style", "Message type (MSGStyle enum): PAM_PROMPT_ECHO_OFF, "
		      "PAM_PROMPT_ECHO_ON, PAM_ERROR_MSG, or PAM_TEXT_INFO"},
	{"msg", "Message text from PAM module"},
	{0},
};

PyStructSequence_Desc struct_pam_msg_desc = {
	.name = MODULE_NAME ".struct_pam_message",
	.fields = struct_pam_msg,
	.doc = "Python wrapper around struct pam_message from pam_conv(3).\n\n"
	       "Represents a single message in the PAM conversation mechanism.\n"
	       "PAM modules use this structure to communicate with applications\n"
	       "through the conversation callback function.",
	.n_in_sequence = 2
};

#define MSG_STYLE_IDX 0
#define MSG_DATA_IDX 1

static
PyObject *py_pam_msg(tnpam_state_t *state, const struct pam_message *msg)
{
	PyObject *entry = NULL;
	PyObject *value = NULL;
	PyObject *style_enum_member = NULL;
	PyObject *style_obj = NULL;

	entry = PyStructSequence_New(state->struct_pam_msg_type);
	if (entry == NULL) {
		return NULL;
	}

	/*
	 * struct pam_message.msg is filled in by the module and libpam does not
	 * guarantee it is non-NULL. PyUnicode_FromString() calls strlen()
	 * unconditionally, so a module that emits an empty prompt would take
	 * down the whole process. Treat it the same way tnpam_collect_conv()
	 * does and substitute an empty string.
	 */
	value = PyUnicode_FromString(msg->msg ? msg->msg : "");
	if (value == NULL) {
		Py_CLEAR(entry);
		return NULL;
	}
	PyStructSequence_SET_ITEM(entry, MSG_DATA_IDX, value);

	// Create MSGStyle enum member for msg_style
	PYPAM_ASSERT((state->msg_style_enum != NULL), "MSGStyle enum not initialized");

	style_obj = PyLong_FromLong(msg->msg_style);
	if (style_obj == NULL) {
		Py_CLEAR(entry);
		return NULL;
	}

	style_enum_member = PyObject_CallFunctionObjArgs(state->msg_style_enum, style_obj, NULL);
	Py_DECREF(style_obj);

	if (style_enum_member == NULL) {
		Py_CLEAR(entry);
		return NULL;
	}
	PyStructSequence_SET_ITEM(entry, MSG_STYLE_IDX, style_enum_member);

	return entry;
}

PyObject *py_pam_messages_parse(int num_msg, const struct pam_message **msg)
{
	PyObject *out = NULL;
	tnpam_state_t *state = NULL;
	int i;
	PyObject *msgs = NULL;

	state = py_get_pam_state(NULL);
	if (state == NULL) {
		return NULL;
	}

	msgs = PyList_New(0);
	if (msgs == NULL) {
		return NULL;
	}

	// we already assert if num_msg is negative
	for (i = 0; i < num_msg; i++) {
		PyObject *entry = NULL;
		int ret;

		entry = py_pam_msg(state, msg[i]);
		if (entry == NULL) {
			Py_CLEAR(msgs);
			return NULL;
		}

		ret = PyList_Append(msgs, entry);
		Py_CLEAR(entry);
		if (ret != 0) {
			Py_CLEAR(msgs);
			return NULL;
		}
	}
	out = PyList_AsTuple(msgs);
	Py_CLEAR(msgs);
	return out;
}

/*
 * Free a response array, scrubbing each response first.
 *
 * The strings here are the answers to PAM prompts, which on the common path
 * means the user's plaintext password. libpam scrubs before freeing in the
 * equivalent places (pam_overwrite_string() in libpam_misc/misc_conv.c and
 * libpam/pam_get_authtok.c), and this library's README undertakes not to keep
 * credentials in plain text, so do the same rather than leaving them intact in
 * a freed heap block.
 */
void free_pam_resp(int num_msg, struct pam_response *reply_array)
{
	int i;

	if (reply_array == NULL) {
		return;
	}

	for (i = 0; i < num_msg; i++) {
		if (reply_array[i].resp != NULL) {
			explicit_bzero(reply_array[i].resp,
				       strlen(reply_array[i].resp));
			free(reply_array[i].resp);
		}
	}

	free(reply_array);
}

/*
 * This function takes the python callback response (which should be an iterable)
 * and converts it into an array of struct pam_response responses from the application
 * to the PAM stack.
 */
bool parse_py_pam_resp(int num_msg, struct pam_response **resp, PyObject *pyresp)
{
	struct pam_response *reply = NULL;
	PyObject *iterator = NULL;
	PyObject *item = NULL;
	const char *rval;
	int i = 0;

	// We should have some sort of iterable from the python callback
	// The iterable should contain either None type (for NULL response)
	// or strings.
	iterator = PyObject_GetIter(pyresp);
	if (iterator == NULL) {
		// We expected an iterable and didn't get it. Python exception
		// will be set in this case.
		return false;
	}

	// PAM expects one response per input message. We'll hope that library
	// consumer keeps order correct.  We *must* use regular malloc rather
	// than PyMem_Raw interface because the memory will be freed by the
	// PAM service module stack.
	reply = calloc(num_msg, sizeof(struct pam_response));
	if (reply == NULL) {
		Py_DECREF(iterator);
		PyErr_NoMemory();
		return false;
	}

	while ((item = PyIter_Next(iterator))) {
		if (i >= num_msg) {
			PyErr_Format(PyExc_ValueError,
				     "response contains more elements "
				     "than expected value of (%d)",
				     num_msg);
			free_pam_resp(num_msg, reply);
			Py_DECREF(item);
			Py_DECREF(iterator);
			return false;
		}

		// Py_None will be treated as msg == NULL which is already set
		// since we used calloc to allocate
		if (item != Py_None) {
			rval = PyUnicode_AsUTF8(item);
			if (rval == NULL) {
				// Exception already est
				free_pam_resp(num_msg, reply);
				Py_DECREF(item);
				Py_DECREF(iterator);
				return false;
			}

			reply[i].resp = strdup(rval);
			if (reply[i].resp == NULL) {
				PyErr_SetString(PyExc_MemoryError,
						"strdup() failed");
				free_pam_resp(num_msg, reply);
				Py_DECREF(item);
				Py_DECREF(iterator);
				return false;
			}
		}
		Py_CLEAR(item);
		i++;
	}

	Py_DECREF(iterator);

	if (i != num_msg) {
		free_pam_resp(num_msg, reply);
		PyErr_Format(PyExc_ValueError,
			     "response contains fewer elements "
			     "than expected value of (%d)",
			     num_msg);
		return false;
	}

	// PAM expects one response per input message. We'll hope that library
	*resp = reply;
	return true;
}

/* pam_conv_t wrapper.
 *
 * This is the hard-coded C callback function which will in turn call our supplied python
 * callback function.
 *
 * The appdata_ptr will be the actual tnpam_ctx_t that started the
 * converstation. There is a conversation-specific struct that contains
 * details such as callback function
 *
 * On error we return PAM_CONV_ERR, set an exception, and hope the module(s) pass back up to
 * caller.
 */
int truenas_pam_conv(int num_msg, const struct pam_message **msg,
		     struct pam_response **resp, void *appdata_ptr)
{
	tnpam_ctx_t *ctx = (tnpam_ctx_t *)appdata_ptr;
	PyObject *pymsg = NULL;
	PyObject *pyresp = NULL;
	int retval = PAM_CONV_ERR;

	PYPAM_ASSERT((ctx != NULL), "Unexpected NULL appdata_ptr");
	PYPAM_ASSERT((num_msg >= 0), "Unexpected negative value for num_msg");
	PYPAM_ASSERT((ctx->conv_type == TNPAM_CONV_CALLBACK), "truenas_pam_conv called on non-callback context");
	PYPAM_ASSERT((ctx->conv_data.py_cb.callback_fn != NULL), "Undefined callback function");

	// Reacquire the GIL to call into Python. The handle lock stays held: the
	// pam_*() call that drove this conversation is still on our stack, so
	// handing the handle back here would let another thread re-enter libpam
	// on it mid-dispatch.
	PYPAM_CONV_GIL_ACQUIRE(ctx);

	// PAM module may be making multiple attempts but we already have errored out
	// from a python perspective
	if (PyErr_Occurred()) {
		// Clear out the error and do the next round of nonsense
		PyErr_Clear();
	}

	pymsg = py_pam_messages_parse(num_msg, msg);
	if (pymsg == NULL) {
		goto cleanup;
	}

	if (PyList_Append(ctx->conv_data.py_cb.messages, pymsg) < 0) {
		goto cleanup;
	}

	pyresp = PyObject_CallFunctionObjArgs(ctx->conv_data.py_cb.callback_fn,
					      ctx,
					      pymsg,
					      ctx->conv_data.py_cb.private_data,
					      NULL);
	if (pyresp == NULL) {
		goto cleanup;
	}

	if (!parse_py_pam_resp(num_msg, resp, pyresp)) {
		goto cleanup;
	}

	retval = PAM_SUCCESS;

cleanup:
	Py_CLEAR(pymsg);
	Py_CLEAR(pyresp);

	// Drop the GIL because we're going back into the wonderful world of pure C
	PYPAM_CONV_GIL_RELEASE(ctx);
	return retval;
}

/*
 * Simple discard conversation function for use during pam_acct_mgmt() in
 * internal thread mode. Account management only emits informational messages
 * (PAM_TEXT_INFO / PAM_ERROR_MSG), not interactive prompts. We allocate
 * zero-filled responses (NULL resp strings are acceptable for info messages).
 */
int
tnpam_discard_conv(int num_msg, const struct pam_message **msg,
		   struct pam_response **resp, void *appdata_ptr)
{
	*resp = calloc(num_msg, sizeof(struct pam_response));
	return (*resp != NULL) ? PAM_SUCCESS : PAM_BUF_ERR;
}

/*
 * Conversation function used for synchronous PAM operations on an
 * internal-thread context. It must not block (unlike tnpam_internal_conv,
 * which waits for the main thread) and must not touch Python objects (the GIL
 * is not held). Message strings are copied with PyMem_RawMalloc (GIL-free) so
 * the caller can convert them once it has the GIL back.
 *
 * Note: *resp is allocated with calloc, not PyMem_Raw*, because libpam owns
 * and frees it with free(). Responses are zero-filled; PAM_TEXT_INFO and
 * PAM_ERROR_MSG do not require a meaningful response string.
 */
int
tnpam_collect_conv(int num_msg, const struct pam_message **msg,
		   struct pam_response **resp, void *appdata_ptr)
{
	struct tnpam_collected_msgs *col = appdata_ptr;
	int i;

	*resp = calloc(num_msg, sizeof(struct pam_response));
	if (*resp == NULL) {
		return PAM_BUF_ERR;
	}

	for (i = 0; i < num_msg; i++) {
		const char *src = msg[i]->msg ? msg[i]->msg : "";
		size_t len = strlen(src) + 1;
		char *copy;

		if (col->count >= TNPAM_COLLECT_MSG_BUF) {
			break;
		}

		copy = PyMem_RawMalloc(len);
		if (copy == NULL) {
			/* OOM — skip this message rather than abort */
			continue;
		}
		memcpy(copy, src, len);
		col->msg_styles[col->count] = msg[i]->msg_style;
		col->msgs[col->count] = copy;
		col->count++;
	}

	return PAM_SUCCESS;
}

/*
 * Convert the collected messages to Python and append them to the context's
 * message history. Caller must hold the GIL. Always drains the buffer.
 */
static void
tnpam_drain_collected(tnpam_ctx_t *ctx)
{
	struct tnpam_collected_msgs *col = &ctx->conv_data.th_cb.collected;
	struct pam_message msgs_tmp[TNPAM_COLLECT_MSG_BUF];
	const struct pam_message *msgs_ptr[TNPAM_COLLECT_MSG_BUF];
	PyObject *pymsg;
	int i;

	if (col->count == 0) {
		return;
	}

	for (i = 0; i < col->count; i++) {
		msgs_tmp[i].msg_style = col->msg_styles[i];
		msgs_tmp[i].msg = col->msgs[i];
		msgs_ptr[i] = &msgs_tmp[i];
	}

	pymsg = py_pam_messages_parse(col->count, msgs_ptr);
	if (pymsg != NULL) {
		if (PyList_Append(ctx->conv_data.th_cb.messages, pymsg) < 0) {
			PyErr_Clear();
		}
		Py_DECREF(pymsg);
	} else {
		PyErr_Clear();
	}

	for (i = 0; i < col->count; i++) {
		PyMem_RawFree(col->msgs[i]);
		col->msgs[i] = NULL;
	}
	col->count = 0;
}

bool
tnpam_call_pam_op(tnpam_ctx_t *ctx, tnpam_pam_op_fn op, int flags,
		  pamcode_t *out)
{
	pamcode_t ret;
	pamcode_t swap_in = PAM_SUCCESS;
	pamcode_t swap_back = PAM_SUCCESS;

	if (ctx->conv_type != TNPAM_CONV_INTERNAL_THREAD) {
		PYPAM_LOCK(ctx);
		ret = op(ctx->hdl, flags);
		ctx->last_pam_result = ret;
		PYPAM_UNLOCK(ctx);
		*out = ret;
		return true;
	}

	/*
	 * appdata_ptr must outlive this frame: pam_set_item() copies the
	 * pam_conv struct (libpam/pam_item.c) but not what it points at, and a
	 * failed restore below leaves the collector installed on the handle.
	 */
	struct pam_conv collect_conv = {
		.conv = tnpam_collect_conv,
		.appdata_ptr = &ctx->conv_data.th_cb.collected,
	};

	memset(&ctx->conv_data.th_cb.collected, 0,
	       sizeof(ctx->conv_data.th_cb.collected));

	PYPAM_LOCK(ctx);
	swap_in = pam_set_item(ctx->hdl, PAM_CONV, &collect_conv);
	if (swap_in == PAM_SUCCESS) {
		ret = op(ctx->hdl, flags);
		ctx->last_pam_result = ret;
		swap_back = pam_set_item(ctx->hdl, PAM_CONV, &ctx->conv);
	}
	PYPAM_UNLOCK(ctx);

	/* GIL is held again from here. */
	if (swap_in != PAM_SUCCESS) {
		set_pam_exc(swap_in, "pam_set_item() failed to install the "
				     "collector conversation");
		return false;
	}

	tnpam_drain_collected(ctx);

	if (swap_back != PAM_SUCCESS) {
		/*
		 * The handle still has the collector installed. That is safe --
		 * it never blocks and its buffer is owned by this context -- but
		 * an authentication driven through it would silently answer
		 * every prompt with NULL, so fail loudly rather than continue.
		 */
		set_pam_exc(swap_back, "pam_set_item() failed to restore the "
				       "conversation");
		return false;
	}

	*out = ret;
	return true;
}

/*
 * Internal conversation function used in internal pthread mode. Called by
 * pam_authenticate() on the auth thread. Signals the main thread with the
 * pending messages and waits for responses — all via pure C pthreads with
 * no GIL involvement.
 */
int
tnpam_internal_conv(int num_msg, const struct pam_message **msg,
		    struct pam_response **resp, void *appdata_ptr)
{
	tnpam_ctx_t *ctx = appdata_ptr;
	int final_state;

	PYPAM_ASSERT((ctx != NULL), "Unexpected NULL appdata_ptr");
	PYPAM_ASSERT((ctx->conv_type == TNPAM_CONV_INTERNAL_THREAD), "tnpam_internal_conv called on non-thread context");

	pthread_mutex_lock(&ctx->conv_data.th_cb.conv_mutex);

	/* Dealloc may have set CANCELLED before we entered — honour it immediately. */
	if (ctx->conv_data.th_cb.conv_state == THREAD_STATE_CONV_CANCELLED) {
		pthread_mutex_unlock(&ctx->conv_data.th_cb.conv_mutex);
		return PAM_CONV_ERR;
	}

	ctx->conv_data.th_cb.pending_msgs = msg;
	ctx->conv_data.th_cb.num_pending_msgs = num_msg;
	ctx->conv_data.th_cb.conv_state = THREAD_STATE_CONV_PENDING;
	pthread_cond_signal(&ctx->conv_data.th_cb.conv_cond_main);  /* wake main thread */

	/*
	 * Hand the PAM handle back while we are parked. The pam_*() call that
	 * drove this conversation is suspended here, inside our own conversation
	 * function, so no module code can touch the handle until we return, and
	 * the Python thread composing the response is free to use the context in
	 * the meantime. Dropped before the wait and retaken only after conv_mutex
	 * is released, so the lock order is always pam_hdl_lock -> conv_mutex.
	 */
	tnpam_hdl_unlock(&ctx->pam_hdl_lock);

	while (ctx->conv_data.th_cb.conv_state == THREAD_STATE_CONV_PENDING) {
		pthread_cond_wait(&ctx->conv_data.th_cb.conv_cond_auth, &ctx->conv_data.th_cb.conv_mutex);
	}

	final_state = ctx->conv_data.th_cb.conv_state;
	if (final_state != THREAD_STATE_CONV_CANCELLED) {
		/* CONV_RESPONDED: pick up responses (ownership transferred to PAM) */
		*resp = ctx->conv_data.th_cb.pending_resps;
		ctx->conv_data.th_cb.pending_resps = NULL;
	} else {
		/*
		 * Cancelled after continue_authentication() had already handed
		 * us responses (it stores them, then waits with a deadline, so a
		 * timeout can land between the two). Nobody else will consume
		 * them, and they hold the user's plaintext password, so scrub
		 * and free rather than leaking them for the life of the process.
		 */
		free_pam_resp(ctx->conv_data.th_cb.num_pending_msgs,
			      ctx->conv_data.th_cb.pending_resps);
		ctx->conv_data.th_cb.pending_resps = NULL;
	}
	pthread_mutex_unlock(&ctx->conv_data.th_cb.conv_mutex);

	/* Reclaim the handle before returning into libpam. */
	tnpam_hdl_lock(&ctx->pam_hdl_lock);

	return (final_state == THREAD_STATE_CONV_CANCELLED) ? PAM_CONV_ERR : PAM_SUCCESS;
}

/*
 * Initialize python structs and enums related to pam conversations and store
 * references in the module state.
 */
bool init_pam_conv_struct(PyObject *module_ref)
{
	PyTypeObject *obj = NULL;
	tnpam_state_t *state = NULL;
	PyObject *msg_style_enum = NULL;

	state = py_get_pam_state(module_ref);
	if (state == NULL)
		return false;

	obj = PyStructSequence_NewType(&struct_pam_msg_desc);
	if (obj == NULL)
		return false;

	state->struct_pam_msg_type = obj;

	// Create and add MSGStyle IntEnum
	msg_style_enum = create_msg_style_enum();
	if (msg_style_enum == NULL) {
		return false;
	}

	if (PyModule_AddObjectRef(module_ref, "MSGStyle", msg_style_enum) < 0) {
		Py_DECREF(msg_style_enum);
		return false;
	}

	// Store reference in module state
	state->msg_style_enum = msg_style_enum;

	return true;
}
