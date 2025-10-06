// SPDX-License-Identifier: LGPL-3.0-or-later
#ifndef TRUENAS_PYPAM_H
#define TRUENAS_PYPAM_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdbool.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#define MODULE_NAME "truenas_pypam"

/* libpam doesn't do us any favors here. Typedef is to just
 * make this library a little clearer to future developers
 */
typedef int pamcode_t;
typedef int boolean_t;

#define B_TRUE 1
#define B_FALSE 0

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

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
 * Macros to handle taking lock and dropping GIL
 */
#define PYPAM_LOCK(ctx) do { \
	pthread_mutex_lock(&ctx->pam_hdl_lock); \
	ctx->_save = PyEval_SaveThread(); \
} while (0);

#define PYPAM_UNLOCK(ctx) do { \
	PyEval_RestoreThread(ctx->_save); \
	pthread_mutex_unlock(&ctx->pam_hdl_lock); \
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
 * @brief Library appdata type to pass as part of struct pam_conv
 *
 * This structure holds state information for the pam_conv callback from
 * PAM modules. It provides a pointer to a python callable provided by
 * library user and private data also provided by the library user.
 * Messages received from the server (which are not sensitive) are stored
 * as a list here.
 *
 * @note This is not a python structure
 */
typedef struct {
	PyObject *callback_fn;
	PyObject *private_data;
	PyObject *messages;
} tnpam_conv_t;

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
	pthread_mutex_t pam_hdl_lock;
	// Store thread state in handle since we have conversation callbacks where
	// we need to reacquire the GIL
	PyThreadState *_save;
	pam_handle_t *hdl;
	tnpam_conv_t conv_data;
	struct pam_conv conv;
	PyObject *user;
	boolean_t authenticated;
	boolean_t session_opened;
	pamcode_t last_pam_result;
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

/* provided by py_env.c */
PyDoc_STRVAR(py_tnpam_getenv__doc__,
"get_env(*, name) -> str\n"
"-----------------------\n\n"
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
extern bool init_pam_conv_struct(PyObject *module_ref);

/* provided by py_error.c */
extern bool setup_pam_exception(PyObject *module_ref);
extern PyObject *py_pamcode_dict(void);
extern void _set_pam_exc(int code, const char *additional_info, const char *location);

#define __stringify(x) #x
#define __stringify2(x) __stringify(x)
#define __location__ __FILE__ ":" __stringify2(__LINE__)

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
