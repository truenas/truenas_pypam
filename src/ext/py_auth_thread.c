// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * Internal C pthread-based authentication for PAM contexts created without a
 * Python conversation_function.  All synchronization is pure pthreads; the
 * GIL is never held inside the auth thread or tnpam_internal_conv.
 *
 * Primitives
 * ----------
 *   conv_mutex      - guards conv_state and all th_cb fields
 *   conv_cond_main  - main thread waits here; auth thread (via
 *                     tnpam_internal_conv) and the final AUTH_DONE
 *                     transition signal it
 *   conv_cond_auth  - auth thread waits here (inside tnpam_internal_conv);
 *                     main thread signals it from continue_authentication()
 *                     or _tnpam_cancel_auth_thread()
 *
 * State machine / locking diagram (ASCII)
 * ----------------------------------------
 *
 *  MAIN THREAD  (holds GIL except where noted)
 *  |
 *  | begin_authentication():
 *  |   lock(conv_mutex)
 *  |   conv_state = AUTH_RUNNING
 *  |   unlock(conv_mutex)
 *  |   pthread_create() ----------------------------------------+
 *  |   [drop GIL]                                               |
 *  |   lock(conv_mutex)                           AUTH THREAD   |
 *  |   while state == AUTH_RUNNING:               (no GIL ever) |
 *  |     wait(conv_cond_main, conv_mutex)  <----+               |
 *  |                                            |  pam_authenticate()
 *  |                                            |    calls tnpam_internal_conv():
 *  |                                            |      lock(conv_mutex)
 *  |                                            |      pending_msgs = msgs
 *  |                                            |      conv_state = CONV_PENDING
 *  |                                            +-- signal(conv_cond_main)
 *  |   -- wakes: state == CONV_PENDING --           unlock(conv_mutex)
 *  |   unlock(conv_mutex)                           wait(conv_cond_auth,
 *  |   [regain GIL]                                      conv_mutex) <--+
 *  |   return messages tuple (Python)                                    |
 *  |                                                                     |
 *  | continue_authentication(responses):                                 |
 *  |   [drop GIL]                                                        |
 *  |   lock(conv_mutex)                                                  |
 *  |   pending_resps = responses                                         |
 *  |   conv_state = CONV_RESPONDED                                       |
 *  |   signal(conv_cond_auth) ------------------------------------------+
 *  |   while state == CONV_RESPONDED:         -- wakes, state == CONV_RESPONDED --
 *  |     wait(conv_cond_main, conv_mutex)<--+    unlock(conv_mutex)
 *  |                                        |    [read pending_resps, free old]
 *  |                                        |    pam_authenticate() continues
 *  |                                        |
 *  |                                        |  (if PAM requests another round:
 *  |                                        |   tnpam_internal_conv() runs again,
 *  |                                        |   state -> CONV_PENDING,
 *  |                                        +-- signal(conv_cond_main))
 *  |
 *  |                                           (when pam_authenticate() returns:)
 *  |                                             lock(conv_mutex)
 *  |                                             auth_result = ret
 *  |                                             conv_state = AUTH_DONE
 *  |   -- wakes: state == AUTH_DONE --  <------- signal(conv_cond_main)
 *  |   unlock(conv_mutex)                        unlock(conv_mutex)
 *  |   [regain GIL]                              [thread exits]
 *  |   pthread_join()
 *  |   return None on PAM_SUCCESS / raise PAMError
 *  |
 *  | Cancellation (_tnpam_cancel_auth_thread, called on timeout or dealloc):
 *  |   lock(conv_mutex)
 *  |   conv_state = CONV_CANCELLED
 *  |   signal(conv_cond_auth) --> [if blocked in tnpam_internal_conv:
 *  |   unlock(conv_mutex)           wakes, sees CANCELLED, returns empty
 *  |   [drop GIL]                   responses so pam_authenticate() can
 *  |   pthread_join()               unwind cleanly and the thread exits]
 */
#define PY_SSIZE_T_CLEAN
#include <signal.h>
#include <string.h>
#include "truenas_pypam.h"

/*
 * Auth thread entry point. Calls pam_authenticate() and on return signals the
 * main thread with the result. Never touches Python objects or the GIL.
 */
static void *
tnpam_auth_thread_func(void *arg)
{
	tnpam_ctx_t *ctx = arg;
	sigset_t all;

	/*
	 * Block all signals in the auth thread.  Signal delivery (SIGINT etc.)
	 * must happen on the main thread so that Python's signal machinery
	 * fires correctly.  Inheriting the main thread's mask would allow
	 * signals to land here instead, silently suppressing KeyboardInterrupt.
	 * PAM modules may also block in I/O; a signal interrupting them
	 * mid-call could leave PAM state inconsistent.
	 */
	sigfillset(&all);
	pthread_sigmask(SIG_BLOCK, &all, NULL);

	/*
	 * Serialize against the Python-facing methods for as long as libpam is
	 * actually executing: a PAM handle is not thread-safe, and modules mutate
	 * items on it (pam_set_item(PAM_USER) and friends free and replace the
	 * strings that ctx.user reads). tnpam_internal_conv() hands the lock back
	 * while it parks, so the Python thread is still free to use the context
	 * between begin_authentication() and continue_authentication().
	 *
	 * This thread has no PyThreadState, so PyMutex parks it on a plain
	 * semaphore rather than touching the GIL.
	 */
	tnpam_hdl_lock(&ctx->pam_hdl_lock);
	pamcode_t ret = pam_authenticate(ctx->hdl, ctx->conv_data.th_cb.auth_flags);
	tnpam_hdl_unlock(&ctx->pam_hdl_lock);

	pthread_mutex_lock(&ctx->conv_data.th_cb.conv_mutex);
	ctx->conv_data.th_cb.auth_result = ret;
	ctx->conv_data.th_cb.conv_state = THREAD_STATE_AUTH_DONE;
	pthread_cond_signal(&ctx->conv_data.th_cb.conv_cond_main);
	pthread_mutex_unlock(&ctx->conv_data.th_cb.conv_mutex);
	return NULL;
}

/*
 * Convert a pre-parsed timeout in seconds (0 = no timeout) into an absolute
 * CLOCK_MONOTONIC deadline.  Rejects negative values and values above
 * TNPAM_TIMEOUT_MAX_SECS.  Returns false (with a Python exception set) on
 * error.
 *
 * Parsed with the "i" format unit, not "I": "I" converts via
 * PyLong_AsUnsignedLongMask(), which masks out-of-range values instead of
 * raising, and 0 here means "wait indefinitely".
 *
 * CLOCK_MONOTONIC, matching the condition variables' clock attribute. An
 * absolute wall-clock deadline moves when the wall clock does, so an NTP
 * correction during a login either fires the timeout instantly or pushes it
 * out of reach.
 */
#define TNPAM_TIMEOUT_MAX_SECS 300

static bool
_tnpam_make_deadline(int secs, bool *has_timeout,
		     struct timespec *deadline)
{
	*has_timeout = false;

	if (secs == 0) {
		return true;
	}

	if (secs < 0) {
		PyErr_SetString(PyExc_ValueError, "timeout must not be negative");
		return false;
	}

	if (secs > TNPAM_TIMEOUT_MAX_SECS) {
		PyErr_Format(PyExc_ValueError,
			     "timeout must not exceed %d seconds", TNPAM_TIMEOUT_MAX_SECS);
		return false;
	}

	if (clock_gettime(CLOCK_MONOTONIC, deadline) != 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return false;
	}

	deadline->tv_sec += (time_t)secs;
	*has_timeout = true;
	return true;
}

/*
 * Drop the GIL and block on conv_cond_main until thread_conv_state differs
 * from wait_while_state (or the timeout fires).
 *
 * Returns the final thread_conv_state observed after re-acquiring the GIL.
 * Sets *timed_out=true if the wait timed out.
 *
 * Caller must hold the GIL and must NOT hold conv_mutex.
 */
static int
_tnpam_wait_conv_or_done(tnpam_ctx_t *ctx, int wait_while_state,
			 bool has_timeout, struct timespec *deadline,
			 bool *timed_out)
{
	int final_state;
	*timed_out = false;

	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&ctx->conv_data.th_cb.conv_mutex);

	while (ctx->conv_data.th_cb.conv_state == wait_while_state) {
		int rc;
		if (has_timeout) {
			rc = pthread_cond_timedwait(&ctx->conv_data.th_cb.conv_cond_main,
						    &ctx->conv_data.th_cb.conv_mutex, deadline);
			if (rc == ETIMEDOUT) {
				*timed_out = true;
				break;
			}
		} else {
			pthread_cond_wait(&ctx->conv_data.th_cb.conv_cond_main, &ctx->conv_data.th_cb.conv_mutex);
		}
	}

	final_state = ctx->conv_data.th_cb.conv_state;
	pthread_mutex_unlock(&ctx->conv_data.th_cb.conv_mutex);
	Py_END_ALLOW_THREADS

	return final_state;
}

/*
 * Cancel a running auth thread. Signals the auth thread if it is blocked in
 * tnpam_internal_conv (CONV_PENDING), then joins. GIL is held on entry.
 *
 * Note the join is not bounded. A PAM module cannot be safely aborted mid-call
 * -- pthread_cancel() would leave the handle and the module's own state
 * inconsistent -- so cancellation can only take effect once the module next
 * returns to our conversation function. If a module is wedged in I/O the join
 * waits for it. The timeout therefore bounds the conversation round trip, not
 * an unresponsive module; see the begin_authentication() documentation.
 */
static void
_tnpam_cancel_auth_thread(tnpam_ctx_t *ctx)
{
	pthread_mutex_lock(&ctx->conv_data.th_cb.conv_mutex);
	if (ctx->conv_data.th_cb.conv_state != THREAD_STATE_AUTH_DONE) {
		ctx->conv_data.th_cb.conv_state = THREAD_STATE_CONV_CANCELLED;
		pthread_cond_signal(&ctx->conv_data.th_cb.conv_cond_auth);
	}
	pthread_mutex_unlock(&ctx->conv_data.th_cb.conv_mutex);

	Py_BEGIN_ALLOW_THREADS
	pthread_join(ctx->conv_data.th_cb.auth_thread, NULL);
	Py_END_ALLOW_THREADS

	ctx->conv_data.th_cb.thread_joined = B_TRUE;

	/*
	 * Carry the real pam_authenticate() result forward so pam_end() is told
	 * the authentication failed. Leaving last_pam_result at its PAM_SUCCESS
	 * default reports an abandoned or timed-out login to every module's
	 * cleanup handler as a completed one.
	 */
	ctx->last_pam_result = ctx->conv_data.th_cb.auth_result;
}

/*
 * Shared final-state handler called after _tnpam_wait_conv_or_done() returns.
 *
 *   CONV_PENDING  → build and return a Python messages tuple
 *   AUTH_DONE     → join thread, return None on success or raise PAMError
 */
static PyObject *
_tnpam_process_state(tnpam_ctx_t *ctx, int state)
{
	if (state == THREAD_STATE_CONV_PENDING) {
		PyObject *pymsg = py_pam_messages_parse(
			ctx->conv_data.th_cb.num_pending_msgs,
			ctx->conv_data.th_cb.pending_msgs);
		if (pymsg == NULL)
			return NULL;
		if (PyList_Append(ctx->conv_data.th_cb.messages, pymsg) < 0) {
			Py_DECREF(pymsg);
			return NULL;
		}
		return pymsg;
	}

	if (state == THREAD_STATE_AUTH_DONE) {
		Py_BEGIN_ALLOW_THREADS
		pthread_join(ctx->conv_data.th_cb.auth_thread, NULL);
		Py_END_ALLOW_THREADS
		ctx->conv_data.th_cb.thread_joined = B_TRUE;

		pamcode_t result = ctx->conv_data.th_cb.auth_result;
		ctx->last_pam_result = result;

		if (result != PAM_SUCCESS) {
			if (!PyErr_Occurred()) {
				set_pam_exc(result, "pam_authenticate() failed");
			}
			return NULL;
		}

		ctx->authenticated = B_TRUE;
		Py_RETURN_NONE;
	}

	PyErr_SetString(PyExc_RuntimeError, "unexpected internal thread state");
	return NULL;
}

PyObject *
py_tnpam_begin_authentication(tnpam_ctx_t *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"silent",
		"disallow_null_authtok",
		"timeout",
		NULL
	};
	boolean_t silent = B_FALSE;
	boolean_t disallow_null_authtok = B_FALSE;
	int timeout_secs = 0;
	int flags = 0;
	bool has_timeout = false;
	struct timespec deadline;
	bool timed_out;
	int final_state;
	int err;

	if (!self->conv_type == TNPAM_CONV_INTERNAL_THREAD) {
		PyErr_SetString(PyExc_RuntimeError,
				"begin_authentication() requires a context "
				"created without a conversation_function");
		return NULL;
	}

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$ppi", kwlist,
					 &silent,
					 &disallow_null_authtok,
					 &timeout_secs)) {
		return NULL;
	}

	if (!_tnpam_make_deadline(timeout_secs, &has_timeout, &deadline)) {
		return NULL;
	}

	if (silent) {
		flags |= PAM_SILENT;
	}
	if (disallow_null_authtok) {
		flags |= PAM_DISALLOW_NULL_AUTHTOK;
	}

	pthread_mutex_lock(&self->conv_data.th_cb.conv_mutex);
	if (self->conv_data.th_cb.conv_state != THREAD_STATE_IDLE) {
		pthread_mutex_unlock(&self->conv_data.th_cb.conv_mutex);
		PyErr_SetString(PyExc_RuntimeError,
				"authentication already in progress or completed");
		return NULL;
	}
	self->conv_data.th_cb.auth_flags = flags;
	self->conv_data.th_cb.conv_state = THREAD_STATE_AUTH_RUNNING;
	pthread_mutex_unlock(&self->conv_data.th_cb.conv_mutex);

	if (PySys_Audit(MODULE_NAME ".authenticate", "O", self->user) < 0) {
		pthread_mutex_lock(&self->conv_data.th_cb.conv_mutex);
		self->conv_data.th_cb.conv_state = THREAD_STATE_IDLE;
		pthread_mutex_unlock(&self->conv_data.th_cb.conv_mutex);
		return NULL;
	}

	err = pthread_create(&self->conv_data.th_cb.auth_thread, NULL, tnpam_auth_thread_func, self);
	if (err != 0) {
		pthread_mutex_lock(&self->conv_data.th_cb.conv_mutex);
		self->conv_data.th_cb.conv_state = THREAD_STATE_IDLE;
		pthread_mutex_unlock(&self->conv_data.th_cb.conv_mutex);
		PyErr_Format(PyExc_RuntimeError,
			     "pthread_create() failed: %s", strerror(err));
		return NULL;
	}
	self->conv_data.th_cb.thread_started = B_TRUE;

	final_state = _tnpam_wait_conv_or_done(self, THREAD_STATE_AUTH_RUNNING,
					       has_timeout, &deadline, &timed_out);

	if (timed_out) {
		_tnpam_cancel_auth_thread(self);
		PyErr_SetString(PyExc_TimeoutError, "authentication timed out");
		return NULL;
	}

	return _tnpam_process_state(self, final_state);
}

PyObject *
py_tnpam_continue_authentication(tnpam_ctx_t *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {
		"responses",
		"timeout",
		NULL
	};
	PyObject *pyresp = NULL;
	int timeout_secs = 0;
	struct pam_response *resp = NULL;
	bool has_timeout = false;
	struct timespec deadline;
	bool timed_out = false;
	int final_state;
	int num_msgs;

	if (!self->conv_type == TNPAM_CONV_INTERNAL_THREAD) {
		PyErr_SetString(PyExc_RuntimeError,
				"continue_authentication() requires a context "
				"created without a conversation_function");
		return NULL;
	}

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|$i", kwlist,
					 &pyresp,
					 &timeout_secs)) {
		return NULL;
	}

	pthread_mutex_lock(&self->conv_data.th_cb.conv_mutex);
	int state = self->conv_data.th_cb.conv_state;
	num_msgs = self->conv_data.th_cb.num_pending_msgs;
	pthread_mutex_unlock(&self->conv_data.th_cb.conv_mutex);

	if (state != THREAD_STATE_CONV_PENDING) {
		PyErr_SetString(PyExc_RuntimeError,
				"no conversation pending; call begin_authentication() "
				"first or check the return value of the previous call");
		return NULL;
	}

	if (!_tnpam_make_deadline(timeout_secs, &has_timeout, &deadline)) {
		return NULL;
	}

	/* Parse Python responses while the GIL is held */
	if (!parse_py_pam_resp(num_msgs, &resp, pyresp)) {
		return NULL;
	}

	/*
	 * Store responses, transition to CONV_RESPONDED, signal the auth
	 * thread, then drop the GIL and wait for the next state change.
	 */
	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->conv_data.th_cb.conv_mutex);
	self->conv_data.th_cb.pending_resps = resp;
	self->conv_data.th_cb.conv_state = THREAD_STATE_CONV_RESPONDED;
	pthread_cond_signal(&self->conv_data.th_cb.conv_cond_auth);

	while (self->conv_data.th_cb.conv_state == THREAD_STATE_CONV_RESPONDED) {
		int rc;
		if (has_timeout) {
			rc = pthread_cond_timedwait(&self->conv_data.th_cb.conv_cond_main,
						    &self->conv_data.th_cb.conv_mutex, &deadline);
			if (rc == ETIMEDOUT) {
				timed_out = true;
				break;
			}
		} else {
			pthread_cond_wait(&self->conv_data.th_cb.conv_cond_main, &self->conv_data.th_cb.conv_mutex);
		}
	}

	final_state = self->conv_data.th_cb.conv_state;
	pthread_mutex_unlock(&self->conv_data.th_cb.conv_mutex);
	Py_END_ALLOW_THREADS

	if (timed_out) {
		_tnpam_cancel_auth_thread(self);
		PyErr_SetString(PyExc_TimeoutError, "authentication timed out");
		return NULL;
	}

	return _tnpam_process_state(self, final_state);
}
