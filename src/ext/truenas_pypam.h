// SPDX-License-Identifier: LGPL-3.0-or-later
#ifndef TRUENAS_PYPAM_H
#define TRUENAS_PYPAM_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define MODULE_NAME "truenas_pypam"

/* libpam doesn't do us any favors here. Typedef is to just
 * make this library a little clearer to future developers
 */
typedef int pamcode_t;
typedef int boolean_t;

/* Thread conversation state for internal pthread mode */
enum {
	THREAD_STATE_IDLE = 0,
	THREAD_STATE_AUTH_RUNNING,
	THREAD_STATE_CONV_PENDING,
	THREAD_STATE_CONV_RESPONDED,
	THREAD_STATE_AUTH_DONE,
	THREAD_STATE_CONV_CANCELLED,
};

#define B_TRUE 1
#define B_FALSE 0

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define __stringify(x) #x
#define __stringify2(x) __stringify(x)
#define __location__ __FILE__ ":" __stringify2(__LINE__)

/*
 * Macro to handle extreme error case in module. This should only be invoked
 * if an error condition is detected that would make it dangerous to continue.
 * This will call abort() and generate a corefile.
 */
#define __PYPAM_ASSERT_IMPL(test, message, location) do {\
        if (!test) {\
                Py_FatalError(message " [" location "]");\
        }\
} while (0);
#define PYPAM_ASSERT(test, message)\
        __PYPAM_ASSERT_IMPL(test, message, __location__);

/*
 * Lock serializing access to a PAM handle.
 *
 * PyMutex rather than pthread_mutex_t: it works from every context that touches
 * a handle here. On the internal auth thread, which has no PyThreadState at all,
 * it parks on a plain semaphore; on a thread that still holds the GIL it detaches
 * the thread state and releases the GIL for the duration of the wait
 * (_PySemaphore_Wait() in Python/parking_lot.c) instead of deadlocking against a
 * holder that needs the GIL back before it can unlock. PYPAM_LOCK() drops the GIL
 * before taking the lock, so that second path is a backstop rather than the
 * common case, but it is what makes the lock safe to take from anywhere.
 *
 * The lock is recursive for the thread that owns it: a conversation callback
 * runs nested inside the pam_*() call that already owns the handle and is handed
 * the context object, so it has to be able to read context state without
 * deadlocking against itself.
 *
 * Zero is the unlocked state, which is what tp_alloc() already gives us, and
 * there is nothing to destroy.
 */
typedef struct {
	PyMutex mutex;
	/* (uintptr_t)pthread_self() while held, 0 when unowned */
	_Atomic(uintptr_t) owner;
	/* recursion count, only ever touched by the owning thread */
	unsigned int depth;
} tnpam_hdl_lock_t;

static inline void
tnpam_hdl_lock(tnpam_hdl_lock_t *lock)
{
	uintptr_t self = (uintptr_t)pthread_self();

	PYPAM_ASSERT((self != 0), "pthread_self() returned a null thread identity");

	if (atomic_load_explicit(&lock->owner, memory_order_acquire) == self) {
		lock->depth++;
		return;
	}

	PyMutex_Lock(&lock->mutex);
	atomic_store_explicit(&lock->owner, self, memory_order_release);
	lock->depth = 1;
}

static inline void
tnpam_hdl_unlock(tnpam_hdl_lock_t *lock)
{
	PYPAM_ASSERT((atomic_load_explicit(&lock->owner, memory_order_relaxed) ==
		      (uintptr_t)pthread_self()),
		     "PAM handle lock released by a thread that does not hold it");

	if (--lock->depth > 0) {
		return;
	}

	atomic_store_explicit(&lock->owner, 0, memory_order_release);
	PyMutex_Unlock(&lock->mutex);
}

/*
 * Take the PAM handle and drop the GIL for the duration of the libpam call.
 * Caller must hold the GIL.
 *
 * The GIL is dropped before the handle is taken and taken back only after the
 * handle is released, so neither is ever held while waiting for the other. A
 * thread blocked on the handle therefore cannot pin the GIL (the deadlock), and
 * the handle is never held across a GIL acquisition, which would funnel every
 * other thread through one GIL handoff per operation.
 *
 * ctx->_save is written and read under the handle lock, so the single slot is
 * safe: only the owning thread touches it, and a nested acquisition from a
 * conversation callback stores the same thread's state back into it.
 */
#define PYPAM_LOCK(ctx) do { \
	PyThreadState *_pypam_ts = PyEval_SaveThread(); \
	tnpam_hdl_lock(&(ctx)->pam_hdl_lock); \
	(ctx)->_save = _pypam_ts; \
} while (0);

#define PYPAM_UNLOCK(ctx) do { \
	PyThreadState *_pypam_ts = (ctx)->_save; \
	tnpam_hdl_unlock(&(ctx)->pam_hdl_lock); \
	PyEval_RestoreThread(_pypam_ts); \
} while (0);

/*
 * Take the GIL back inside a conversation function, and give it up again on the
 * way out, without handing back the PAM handle. The pam_*() call that drove the
 * conversation is still on our stack, so releasing the handle here would let
 * another thread re-enter libpam on a handle that is mid-dispatch.
 */
#define PYPAM_CONV_GIL_ACQUIRE(ctx) do { \
	PyEval_RestoreThread((ctx)->_save); \
} while (0);

#define PYPAM_CONV_GIL_RELEASE(ctx) do { \
	(ctx)->_save = PyEval_SaveThread(); \
} while (0);


/**
 * @brief Module state for the truenas_pypam Python extension
 *
 * This structure holds the global state for the Python module,
 * including custom exception objects that are used throughout
 * the module for error reporting.
 */
typedef struct {
	PyObject *pam_error;  /**< Custom exception object for PAM errors */
	PyTypeObject *struct_pam_msg_type;
	PyObject *pam_code_enum;  /**< PAMCode IntEnum */
	PyObject *msg_style_enum;  /**< MSGStyle IntEnum */
	PyObject *cred_op_enum;  /**< CredOp IntEnum */
} tnpam_state_t;

/**
 * @brief Selects which conversation mode a PAM context uses.
 */
typedef enum {
	TNPAM_CONV_CALLBACK = 0,       /* Python callable provided by library user */
	TNPAM_CONV_INTERNAL_THREAD,    /* Internal C pthread; no Python callback */
} tnpam_conv_type_t;

/**
 * @brief Conversation state for callback mode.
 *
 * Holds the Python callable and associated data. Only valid when
 * conv_type == TNPAM_CONV_CALLBACK.
 *
 * @note This is not a Python structure.
 */
typedef struct {
	PyObject *callback_fn;
	PyObject *private_data;
	PyObject *messages;
} tnpam_conv_t;

/*
 * Upper bound on the messages collected from a single non-interactive PAM
 * operation in internal-thread mode. Account management and session
 * setup/teardown only emit informational messages (PAM_TEXT_INFO /
 * PAM_ERROR_MSG), never interactive prompts, so eight is well beyond what any
 * real module sends.
 */
#define TNPAM_COLLECT_MSG_BUF 8

/*
 * Message buffer filled by tnpam_collect_conv().
 *
 * This lives in the context rather than on the caller's stack on purpose. It
 * is handed to libpam as pam_conv.appdata_ptr, and pam_set_item(PAM_CONV) can
 * fail (it mallocs a copy, see libpam/pam_item.c), leaving the collector
 * installed on the handle. A stack-owned buffer would then be written through
 * by any later conversation on a frame that has already returned.
 */
struct tnpam_collected_msgs {
	int count;
	int msg_styles[TNPAM_COLLECT_MSG_BUF];
	char *msgs[TNPAM_COLLECT_MSG_BUF];
};

/**
 * @brief Conversation state for internal pthread mode.
 *
 * Used when a PAM context is created without a conversation_function. All
 * synchronization is pure pthreads; the GIL is never held by the auth thread
 * or tnpam_internal_conv. Only valid when conv_type == TNPAM_CONV_INTERNAL_THREAD.
 */
typedef struct {
	pthread_t auth_thread;
	boolean_t thread_started;
	boolean_t thread_joined;
	/*
	 * True once conv_mutex and both condition variables have been
	 * successfully initialized. tp_init can fail before that point (a bad
	 * service name fails pam_start_confdir first), and destroying a
	 * never-initialized pthread object is undefined.
	 */
	boolean_t sync_ready;

	/* Condition variables for conversation sync */
	pthread_mutex_t conv_mutex;
	pthread_cond_t conv_cond_main;  /* main thread waits here */
	pthread_cond_t conv_cond_auth;  /* auth thread waits here */

	/* Conversation exchange — protected by conv_mutex */
	int conv_state;                 /* THREAD_STATE_* enum */
	const struct pam_message **pending_msgs;
	int num_pending_msgs;
	struct pam_response *pending_resps; /* set by main thread, freed by PAM */
	int auth_flags;
	pamcode_t auth_result;
	PyObject *messages;

	/* Filled by tnpam_collect_conv() during non-interactive operations */
	struct tnpam_collected_msgs collected;
} tnpam_thread_conv_t;

/**
 * @brief Primary python type that wraps around a PAM application (client) handle
 *
 * This is the python type object structure for the entirety of the pam context.
 * An application / client will create a pam handle (wrapped in the context object)
 * and then use it to authenticate, open a session, close session, and maybe change
 * password.
 */
typedef struct {
	PyObject_HEAD
	// PAM handles are not thread-safe and so we need to hold mutex
	// while doing ops using them.
	//
	// WARNING: it's possible that the PAM module itself is not thread-safe
	// in which case the library consumer will need to use a global lock for
	// all PAM contexts.
	//
	// Generally, it's a good idea to avoid putting such modules in the PAM config.
	tnpam_hdl_lock_t pam_hdl_lock;
	// Store thread state in handle since we have conversation callbacks where
	// we need to reacquire the GIL
	PyThreadState *_save;
	pam_handle_t *hdl;
	struct pam_conv conv;
	PyObject *user;
	boolean_t authenticated;
	boolean_t session_opened;
	pamcode_t last_pam_result;

	tnpam_conv_type_t conv_type;
	union {
		tnpam_conv_t py_cb;
		tnpam_thread_conv_t th_cb;
	} conv_data;
} tnpam_ctx_t;

/**
 * @brief External Python type object declarations
 */
extern PyTypeObject PyPamCtx_Type;


/**
 * function definitions
 */
/* provided by truenas_pypam.c */

/**
 * @brief get a borrowed reference to the current module state
 */
extern tnpam_state_t *py_get_pam_state(PyObject *module_in);

/* provided by py_auth.c */
PyDoc_STRVAR(py_tnpam_authenticate__doc__,
"authenticate(*, silent=False, disallow_null_authtok=False) -> None\n"
"------------------------------------------------------------------\n\n"
"Authenticate the user using the configured PAM modules.\n\n"
"This method wraps pam_authenticate(3) and performs user authentication\n"
"according to the PAM service configuration. Multi-step authentication\n"
"is handled through the conversation_function specified when creating\n"
"the PAM context.\n\n"
"The PAM service module may request additional information from the user\n"
"via the conversation_function, such as passwords, PINs, or other\n"
"authentication tokens.\n\n"
"Parameters\n"
"----------\n"
"silent : bool, optional\n"
"    Do not emit any messages during authentication (default=False).\n"
"    Maps to PAM_SILENT flag. See pam_authenticate(3).\n"
"disallow_null_authtok : bool, optional\n"
"    Return PAM_AUTH_ERR if the user does not have a registered\n"
"    authentication token (default=False). Maps to PAM_DISALLOW_NULL_AUTHTOK\n"
"    flag. See pam_authenticate(3).\n\n"
"Raises\n"
"------\n"
"PAMError\n"
"    Authentication failed. The error code attribute contains the PAM return\n"
"    value from pam_authenticate(3):\n"
"    \n"
"    * PAM_AUTH_ERR - The user was not authenticated\n"
"    * PAM_CRED_INSUFFICIENT - Application does not have sufficient\n"
"      credentials to authenticate the user\n"
"    * PAM_AUTHINFO_UNAVAIL - Modules were not able to access the\n"
"      authentication information (network/hardware failure)\n"
"    * PAM_MAXTRIES - One or more authentication modules has reached\n"
"      its limit of tries authenticating the user\n"
"    * PAM_USER_UNKNOWN - User unknown to authentication service\n"
);
extern PyObject *py_tnpam_authenticate(tnpam_ctx_t *self, PyObject *args, PyObject *kwds);
extern PyObject *py_tnpam_begin_authentication(tnpam_ctx_t *self, PyObject *args, PyObject *kwds);
extern PyObject *py_tnpam_continue_authentication(tnpam_ctx_t *self, PyObject *args, PyObject *kwds);

/* provided by py_env.c */
PyDoc_STRVAR(py_tnpam_getenv__doc__,
"get_env(name) -> str\n"
"--------------------\n\n"
"Get the value of a PAM environment variable.\n\n"
"This method wraps pam_getenv(3) and retrieves the value of the\n"
"specified PAM environment variable. PAM environment variables\n"
"are stored in the PAM handle and managed separately from the\n"
"system environment.\n\n"
"WARNING: PAM environment variables should not be used to store\n"
"sensitive information since some PAM applications may copy them\n"
"to regular session environment variables.\n\n"
"Parameters\n"
"----------\n"
"name : str\n"
"    Name of the environment variable to retrieve\n\n"
"Returns\n"
"-------\n"
"str\n"
"    Value of the environment variable\n\n"
"Raises\n"
"------\n"
"FileNotFoundError\n"
"    If the environment variable is not set\n"
);
extern PyObject *py_tnpam_getenv(tnpam_ctx_t *self, PyObject *args, PyObject *kwds);

PyDoc_STRVAR(py_tnpam_setenv__doc__,
"set_env(*, name, value=None, readonly=False) -> None\n"
"-----------------------------------------------------\n\n"
"Set or remove a PAM environment variable.\n\n"
"This method wraps pam_putenv(3) and pam_misc_setenv(3) to set or\n"
"remove PAM environment variables. When value is None or omitted,\n"
"the variable is removed from the PAM environment.\n\n"
"WARNING: PAM environment variables should not be used to store\n"
"sensitive information as they may end up merged into the\n"
"application's overall environment.\n\n"
"Parameters\n"
"----------\n"
"name : str\n"
"    Name of the environment variable\n"
"value : str, optional\n"
"    Value to set (default=None). If None, the variable is removed.\n"
"readonly : bool, optional\n"
"    Set variable as read-only (default=False)\n\n"
"Raises\n"
"------\n"
"PAMError\n"
"    If setting/removing the environment variable fails. Error codes:\n"
"    \n"
"    * PAM_BAD_ITEM - Variable requested for deletion is not set\n"
"ValueError\n"
"    If name parameter is missing\n"
);
extern PyObject *py_tnpam_setenv(tnpam_ctx_t *self, PyObject *args, PyObject *kwds);

PyDoc_STRVAR(py_tnpam_envlist__doc__,
"env_dict() -> dict[str, str]\n"
"-----------------------------\n\n"
"Get all PAM environment variables as a dictionary.\n\n"
"This method wraps pam_getenvlist(3) and returns a complete copy\n"
"of the PAM environment. The PAM environment variables are stored\n"
"in the PAM handle and managed separately from the system\n"
"environment.\n\n"
"WARNING: PAM environment variables should not be used to store\n"
"sensitive information since some PAM applications may copy them\n"
"to regular session environment variables.\n\n"
"Returns\n"
"-------\n"
"dict[str, str]\n"
"    Dictionary mapping environment variable names to their values.\n"
"    Returns an empty dictionary if no variables are set.\n\n"
"Raises\n"
"------\n"
"MemoryError\n"
"    If memory allocation fails\n"
);
extern PyObject *py_tnpam_envlist(tnpam_ctx_t *self, PyObject *Py_UNUSED(ignored));

/* provided by py_acct_mgmt.c */
PyDoc_STRVAR(py_tnpam_acct_mgmt__doc__,
"acct_mgmt(*, silent=False, disallow_null_authtok=False) -> None\n"
"----------------------------------------------------------------\n\n"
"Verify that the authenticated user account is valid and active.\n\n"
"This method wraps pam_acct_mgmt(3) and performs account validation\n"
"checks. It verifies that the user account is valid and active according\n"
"to the PAM service configuration. This includes checking for:\n"
"- Expired passwords\n"
"- Expired accounts\n"
"- Account restrictions (time, access location, etc.)\n"
"- Password aging policies\n\n"
"This function should be called after successful authentication to ensure\n"
"the account is still valid for use.\n\n"
"Parameters\n"
"----------\n"
"silent : bool, optional\n"
"    Do not emit any messages during account validation (default=False).\n"
"    Maps to PAM_SILENT flag. See pam_acct_mgmt(3).\n"
"disallow_null_authtok : bool, optional\n"
"    Return PAM_NEW_AUTHTOK_REQD if the user does not have a registered\n"
"    authentication token (default=False). Maps to PAM_DISALLOW_NULL_AUTHTOK\n"
"    flag. See pam_acct_mgmt(3).\n\n"
"Raises\n"
"------\n"
"PAMError\n"
"    Account validation failed. The error code attribute contains the PAM\n"
"    return value from pam_acct_mgmt(3):\n"
"    \n"
"    * PAM_ACCT_EXPIRED - User account has expired\n"
"    * PAM_AUTH_ERR - Authentication failure\n"
"    * PAM_NEW_AUTHTOK_REQD - User password has expired and must be changed\n"
"    * PAM_PERM_DENIED - Permission denied (account restrictions)\n"
"    * PAM_USER_UNKNOWN - User not known to the underlying account module\n\n"
"Note\n"
"----\n"
"If PAM_NEW_AUTHTOK_REQD is returned, the application should prompt the\n"
"user to change their password using pam_chauthtok(3).\n\n"
"References\n"
"----------\n"
"pam_acct_mgmt(3) - PAM manual page for account management\n"
);
extern PyObject *py_tnpam_acct_mgmt(tnpam_ctx_t *self, PyObject *args, PyObject *kwds);

/* provided by py_chauthtok.c */
PyDoc_STRVAR(py_tnpam_chauthtok__doc__,
"chauthtok(*, silent=False, change_expired_authtok=False) -> None\n"
"-----------------------------------------------------------------\n\n"
"Update the authentication token (password) for the user.\n\n"
"This method wraps pam_chauthtok(3) and is used to change the user's\n"
"authentication token (typically a password). The PAM framework will\n"
"handle prompting for the old password (if required) and the new\n"
"password through the conversation function.\n\n"
"The function operates in two phases:\n"
"1. Preliminary check - verifies the user can change their password\n"
"2. Update phase - actually changes the password\n\n"
"Both phases are handled internally by this single call.\n\n"
"Requires a context created with a conversation_function. A password\n"
"change is inherently interactive, and a context created without one\n"
"answers prompts through begin_authentication()/continue_authentication(),\n"
"which this call has no way to drive. Calling it on such a context raises\n"
"RuntimeError.\n\n"
"Parameters\n"
"----------\n"
"silent : bool, optional\n"
"    Do not emit any messages during the password change (default=False).\n"
"    Maps to PAM_SILENT flag. See pam_chauthtok(3).\n"
"change_expired_authtok : bool, optional\n"
"    Only change the password if it has expired (default=False).\n"
"    If set, the password will only be changed if the account management\n"
"    module returned PAM_NEW_AUTHTOK_REQD during pam_acct_mgmt().\n"
"    Maps to PAM_CHANGE_EXPIRED_AUTHTOK flag.\n\n"
"Raises\n"
"------\n"
"PAMError\n"
"    Password change failed. Common error codes:\n"
"    \n"
"    * PAM_AUTHTOK_ERR - Authentication token manipulation error\n"
"    * PAM_AUTHTOK_RECOVERY_ERR - Failed to recover old authentication token\n"
"    * PAM_AUTHTOK_LOCK_BUSY - Authentication token lock busy\n"
"    * PAM_AUTHTOK_DISABLE_AGING - Aging disabled for authentication token\n"
"    * PAM_PERM_DENIED - Permission denied\n"
"    * PAM_TRY_AGAIN - Preliminary check succeeded but update failed\n"
"    * PAM_USER_UNKNOWN - User not known to the password service\n\n"
"Note\n"
"----\n"
"The conversation function will be called to prompt for:\n"
"- Current password (for verification)\n"
"- New password (possibly twice for confirmation)\n\n"
"The exact prompts depend on the PAM module configuration.\n\n"
"References\n"
"----------\n"
"pam_chauthtok(3) - PAM manual page for password management\n"
);
extern PyObject *py_tnpam_chauthtok(tnpam_ctx_t *self, PyObject *args, PyObject *kwds);

/* provided by py_session.c */
PyDoc_STRVAR(py_tnpam_open_session__doc__,
"open_session(*, silent=False) -> None\n\n"
"Open a PAM session for the authenticated user.\n\n"
"This method wraps pam_open_session(3) and should be called after\n"
"successful authentication. It notifies all loaded modules that a\n"
"new session has been initiated.\n\n"
"Args:\n"
"  silent (bool, optional): If True, suppress informational messages.\n"
"    Maps to PAM_SILENT flag. See pam_open_session(3).\n\n"
"Raises:\n"
"  PAMError: If session opening fails. The exception's code attribute\n"
"    will contain the specific PAMCode enum member indicating the error\n"
"    type from pam_open_session(3).\n\n"
"Note:\n"
"  Sessions should be closed with close_session() when no longer needed.\n"
"  It is an error to open a session without prior authentication.\n\n"
"References:\n"
"  pam_open_session(3) - PAM manual page for session management"
);
extern PyObject *py_tnpam_open_session(tnpam_ctx_t *self, PyObject *args, PyObject *kwds);

PyDoc_STRVAR(py_tnpam_close_session__doc__,
"close_session(*, silent=False) -> None\n\n"
"Close a PAM session for the authenticated user.\n\n"
"This method wraps pam_close_session(3) and should be called to\n"
"properly terminate a session that was opened with open_session().\n"
"It notifies all loaded modules that the session is being terminated.\n\n"
"Args:\n"
"  silent (bool, optional): If True, suppress informational messages.\n"
"    Maps to PAM_SILENT flag. See pam_close_session(3).\n\n"
"Raises:\n"
"  PAMError: If session closing fails. The exception's code attribute\n"
"    will contain the specific PAMCode enum member indicating the error\n"
"    type from pam_close_session(3).\n\n"
"Note:\n"
"  This should be called for every successful open_session() call,\n"
"  even if the session is being terminated abnormally.\n\n"
"References:\n"
"  pam_close_session(3) - PAM manual page for session management"
);
extern PyObject *py_tnpam_close_session(tnpam_ctx_t *self, PyObject *args, PyObject *kwds);

/* provided by py_conv.c */
extern int truenas_pam_conv(int num_msg, const struct pam_message **msg,
			    struct pam_response **resp, void *appdata_ptr);
extern int tnpam_discard_conv(int num_msg, const struct pam_message **msg,
			      struct pam_response **resp, void *appdata_ptr);
/*
 * Free a PAM response array, scrubbing each response string first. Safe to
 * call with a NULL array. Touches no Python API, so it may be called from the
 * auth thread.
 */
extern void free_pam_resp(int num_msg, struct pam_response *reply_array);

/*
 * Non-blocking collector conversation, used for synchronous PAM operations on
 * an internal-thread context. Must not touch Python objects: it runs without
 * the GIL.
 */
extern int tnpam_collect_conv(int num_msg, const struct pam_message **msg,
			      struct pam_response **resp, void *appdata_ptr);

/*
 * Run a synchronous, non-interactive PAM operation (pam_acct_mgmt,
 * pam_open_session, pam_close_session, pam_setcred) on a context.
 *
 * On an internal-thread context the installed conversation is
 * tnpam_internal_conv, which parks the calling thread until
 * continue_authentication() answers it -- and nothing will, because the caller
 * is the thread that would have to. Any module message therefore hangs the
 * caller forever while it holds the handle. Session modules do converse
 * (pam_motd and pam_lastlog both call pam_info), so this is reachable from an
 * ordinary PAM config. Swap in the non-blocking collector for the duration and
 * append whatever the stack emitted to the context's message history.
 *
 * Returns true with *out set to the PAM result, or false with a Python
 * exception set if the conversation could not be swapped.
 */
typedef pamcode_t (*tnpam_pam_op_fn)(pam_handle_t *, int);
extern bool tnpam_call_pam_op(tnpam_ctx_t *ctx, tnpam_pam_op_fn op, int flags,
			      pamcode_t *out);

extern int tnpam_internal_conv(int num_msg, const struct pam_message **msg,
			       struct pam_response **resp, void *appdata_ptr);
extern bool parse_py_pam_resp(int num_msg, struct pam_response **resp, PyObject *pyresp);
extern PyObject *py_pam_messages_parse(int num_msg, const struct pam_message **msg);
extern bool init_pam_conv_struct(PyObject *module_ref);

/* provided by py_error.c */
extern bool setup_pam_exception(PyObject *module_ref);
extern PyObject *py_pamcode_dict(void);
extern void _set_pam_exc(int code, const char *additional_info, const char *location);

#define set_pam_exc(code, additional_info) \
	_set_pam_exc(code, additional_info, __location__)

/* provided by py_ctx.c */

/* provided by py_cred.c */
PyDoc_STRVAR(py_tnpam_setcred__doc__,
"setcred(*, operation, silent=False) -> None\n"
"--------------------------------------------\n\n"
"Establish, maintain, or delete user credentials using pam_setcred(3).\n\n"
"This function is used to establish, maintain and delete the credentials\n"
"of a user. It should be called to set the credentials after a user has\n"
"been authenticated and before a session is opened. The credentials\n"
"should be deleted after the session has been closed.\n\n"
"A credential is something that the user possesses, such as a Kerberos\n"
"ticket, or supplementary group membership that makes up the uniqueness\n"
"of a given user.\n\n"
"Note: The exact behavior depends on the underlying PAM service module\n"
"configuration. Many modules implement this as a no-op.\n\n"
"Parameters\n"
"----------\n"
"operation : CredOp\n"
"    Credential operation to perform. Must be one of:\n"
"    - CredOp.PAM_ESTABLISH_CRED: Initialize credentials for the user\n"
"    - CredOp.PAM_DELETE_CRED: Delete the user's credentials\n"
"    - CredOp.PAM_REINITIALIZE_CRED: Fully reinitialize credentials\n"
"    - CredOp.PAM_REFRESH_CRED: Extend lifetime of existing credentials\n"
"silent : bool, optional\n"
"    If True, PAM modules should not emit informational messages\n"
"    (default=False)\n\n"
"Raises\n"
"------\n"
"PAMError\n"
"    If the credential operation fails. Common error codes:\n"
"    - PAM_BUF_ERR: Memory buffer error\n"
"    - PAM_CRED_ERR: Failed to set user credentials\n"
"    - PAM_CRED_EXPIRED: User credentials expired\n"
"    - PAM_CRED_UNAVAIL: Cannot retrieve user credentials\n"
"    - PAM_SYSTEM_ERR: System error\n"
"    - PAM_USER_UNKNOWN: User not known to authentication module\n\n"
"See Also\n"
"--------\n"
"pam_setcred(3)\n"
);
extern PyObject *py_tnpam_setcred(tnpam_ctx_t *self, PyObject *args, PyObject *kwds);
extern bool setup_cred_op_enum(PyObject *module_ref);

#endif
