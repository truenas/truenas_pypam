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

	value = PyUnicode_FromString(msg->msg);
	if (value == NULL) {
		Py_CLEAR(entry);
		return NULL;
	}
	PyStructSequence_SET_ITEM(entry, 1, value);

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
	PyStructSequence_SET_ITEM(entry, 0, style_enum_member);

	return entry;
}

static
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

static
void free_pam_resp(int num_msg, struct pam_response *reply_array)
{
	int i;

	for (i = 0; i < num_msg; i++) {
		free(reply_array[i].resp);
	}

	free(reply_array);
}

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
		return false;
	}

	// PAM expects one response per input message. We'll hope that library
	// consumer keeps order correct.
	reply = calloc(num_msg, sizeof(struct pam_response));
	if (reply == NULL) {
		Py_DECREF(iterator);
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
	PYPAM_ASSERT((ctx->conv_data.callback_fn != NULL), "Undefined callback function");

	// We need to reacquire GIL and unlock the pam context
	PYPAM_UNLOCK(ctx);

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

	if (PyList_Append(ctx->conv_data.messages, pymsg) < 0) {
		goto cleanup;
	}

	pyresp = PyObject_CallFunctionObjArgs(ctx->conv_data.callback_fn,
					      ctx,
					      pymsg,
					      ctx->conv_data.private_data,
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

	// Drop GIL and grab pthread lock on handle because we're going
	// back into the wonderful world of pure C
	PYPAM_LOCK(ctx);
	return retval;
}

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
