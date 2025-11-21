# TrueNAS Python PAM authenticator
#
# NOTE: this module is currently WIP pending a truenas NSS
# wrapper that will furnish account details and finalized
# work on pam_truenas.

import enum
import queue
import threading
import time
import truenas_pypam
from dataclasses import dataclass
from datetime import datetime, UTC
from typing import Optional, List, Any, Callable


class AuthenticatorStage(enum.StrEnum):
    START = 'START'
    AUTH = 'AUTH'
    OPEN_SESSION = 'OPEN_SESSION'
    CLOSE_SESSION = 'CLOSE_SESSION'
    LOGIN = 'LOGIN'
    LOGOUT = 'LOGOUT'


class AccountFlag(enum.StrEnum):
    # Account-specific flags
    SYS_ADMIN = 'SYS_ADMIN'  # account is root or truenas_admin
    # account is provided by a directory service
    DIRECTORY_SERVICE = 'DIRECTORY_SERVICE'
    # account is provided by the passwd file (and hopefully in our config)
    LOCAL = 'LOCAL'
    ACTIVE_DIRECTORY = 'ACTIVE_DIRECTORY'  # account is provided by AD
    IPA = 'IPA'  # account is provided by FreeIPA
    LDAP = 'LDAP'  # account is provided by ordinary LDAP server

    # Flags about how authenticated
    TWOFACTOR = '2FA'  # Account requires 2FA
    API_KEY = 'API_KEY'  # Account authenticated by API key
    OTPW = 'OTPW'  # Account authenticated by a single-use password
    # Password change for account is required
    PASSWORD_CHANGE_REQUIRED = 'PASSWORD_CHANGE_REQUIRED'


@dataclass(slots=True)
class AuthenticatorState:
    service: str = 'login'
    """ pam service name to be used for handle. """
    stage: AuthenticatorStage = AuthenticatorStage.START
    """ Stage of PAM session / conversation. """
    otpw_possible: bool = True
    """ The authenticator supports authentication using single-use passwords. """
    twofactor_possible: bool = True
    """ The authenticator supports two-factor authentication """
    login_at: datetime | None = None
    """ Time at which session performed actual login """
    passwd: dict | None = None
    """ passwd dict entry for user """
    messages: list | None = None
    """ Messages received during PAM conversation """


@dataclass(slots=True)
class AuthenticatorResponse:
    stage: AuthenticatorStage
    code: truenas_pypam.PAMCode  # PAM response code
    # reason for non-success OR conversation messages when PAM_CONV_AGAIN
    reason: Any
    # passwd dict (only populated on authenticate calls)
    user_info: dict | None = None


@dataclass(slots=True)
class ConversationThreadState:
    """State passed to conversation callback thread"""
    # Thread synchronization
    main_thread_id: int
    input_queue: queue.Queue
    output_queue: queue.Queue
    done_event: threading.Event

    # PAM context parameters (kwargs for truenas_pypam.get_context)
    service_name: str = 'login'  # First positional arg
    user: str = None  # Required kwarg
    conversation_function: Optional[Callable] = None
    # Will be set to self
    conversation_private_data: Any = None
    confdir: Optional[str] = None  # Config directory
    rhost: Optional[str] = None  # Remote host
    ruser: Optional[str] = None  # Remote user
    fail_delay: int = 0  # Fail delay in microseconds
    pam_env: dict[str, str] = None  # PAM environment variables to set

    # Results
    exception: Optional[Exception] = None
    pam_context: Optional[Any] = None  # PAM context on success


def _auth_thread_worker(thread_state: ConversationThreadState):
    """
    Worker thread that performs PAM authentication.
    This is a module-level function to prevent access to instance variables.
    """
    try:
        # Build kwargs dict for get_context
        kwargs = {
            'user': thread_state.user,
            'conversation_function': thread_state.conversation_function,
            # Pass thread_state as private data
            'conversation_private_data': thread_state
        }

        # Add optional parameters if provided
        if thread_state.confdir is not None:
            kwargs['confdir'] = thread_state.confdir
        if thread_state.rhost is not None:
            kwargs['rhost'] = thread_state.rhost
        if thread_state.ruser is not None:
            kwargs['ruser'] = thread_state.ruser
        if thread_state.fail_delay != 0:
            kwargs['fail_delay'] = thread_state.fail_delay

        # Add service_name as keyword argument
        kwargs['service_name'] = thread_state.service_name

        # Create PAM context (all args are keyword-only)
        ctx = truenas_pypam.get_context(**kwargs)

        # Set PAM environment variables if provided
        if thread_state.pam_env:
            for key, value in thread_state.pam_env.items():
                ctx.set_env(name=key, value=value)

        # Perform authentication
        ctx.authenticate()

        # Store context on success
        thread_state.pam_context = ctx

    except Exception as e:
        thread_state.exception = e
    finally:
        thread_state.done_event.set()


def _conv_callback(ctx, messages, private_data: ConversationThreadState):
    """
    PAM conversation callback that runs in authentication thread.
    Communicates with main thread via queues.
    Module-level function to prevent access to instance variables.
    """
    # Verify we're not in the main thread (programming error check)
    if threading.current_thread().ident == private_data.main_thread_id:
        raise RuntimeError(
            "PAM conversation callback called from main thread - "
            "this should not happen"
        )

    # Send messages to main thread
    private_data.output_queue.put(messages)

    # Wait for responses with timeout
    while not private_data.done_event.is_set():
        try:
            responses = private_data.input_queue.get(timeout=1.0)
            return responses
        except queue.Empty:
            continue

    # If done event is set, return empty responses
    return [None] * len(messages)


def _conv_callback_simple(ctx, messages, private_data):
    reply = []
    for m in messages:
        if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            resp = private_data['password']
        elif m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_ON:
            resp = private_data['username']
        else:
            resp = None

        reply.append(resp)

    return reply


class UserPamAuthenticator:
    """
    TrueNAS authenticator object using truenas_pypam extension.
    These are allocated per session and hold an open pam handle with
    state information. Thread-safety is handled by pthread locks in
    the truenas_pypam extension.
    """
    def __init__(
        self,
        *,
        username: str,
        service: str = 'login',
        authentication_timeout: int = 10,
        rhost: Optional[str] = None,
        ruser: Optional[str] = None,
        fail_delay: Optional[int] = None,
        pam_env: Optional[dict[str, str]] = None
    ):
        self.username = username
        self.authentication_timeout = authentication_timeout
        self.rhost = rhost
        self.ruser = ruser
        self.fail_delay = fail_delay
        self.pam_env = pam_env or {}
        self.state = AuthenticatorState(service=service)
        # truenas_pypam context - only set after successful auth
        self.ctx = None
        self._auth_thread = None
        self._thread_state = None

    def check_stage(self, expected: AuthenticatorStage):
        if self.state.stage is not expected:
            raise RuntimeError(
                f'{self.state.stage}: unexpected authenticator run state. '
                f'Expected: {expected}'
            )

    def _wait_for_auth_result(self) -> AuthenticatorResponse:
        """
        Wait for authentication thread to either complete or send conversation request.
        Common logic for auth_init and auth_continue.
        """
        start_time = time.monotonic()
        while not self._thread_state.done_event.is_set():
            # Check timeout
            if time.monotonic() - start_time > self.authentication_timeout:
                self.end()
                return AuthenticatorResponse(
                    AuthenticatorStage.AUTH,
                    truenas_pypam.PAMCode.PAM_SYSTEM_ERR,
                    f"Authentication timeout after "
                    f"{self.authentication_timeout} seconds"
                )

            try:
                # Check for conversation requests
                messages = self._thread_state.output_queue.get(timeout=0.1)
                return AuthenticatorResponse(
                    AuthenticatorStage.AUTH,
                    truenas_pypam.PAMCode.PAM_CONV_AGAIN,
                    messages
                )
            except queue.Empty:
                continue

        # Authentication completed
        self._auth_thread.join()

        if self._thread_state.exception:
            if isinstance(self._thread_state.exception, truenas_pypam.PAMError):
                code = self._thread_state.exception.code
                reason = str(self._thread_state.exception)
            else:
                code = truenas_pypam.PAMCode.PAM_SYSTEM_ERR
                reason = str(self._thread_state.exception)

            self.end()
            return AuthenticatorResponse(AuthenticatorStage.AUTH, code, reason)

        self.ctx = self._thread_state.pam_context
        self.state.stage = AuthenticatorStage.LOGIN
        user_info = {
            'pw_name': self.username,
            'account_attributes': []
        }
        return AuthenticatorResponse(
            AuthenticatorStage.AUTH,
            truenas_pypam.PAMCode.PAM_SUCCESS,
            None,
            user_info
        )

    def auth_init(self) -> AuthenticatorResponse:
        """
        Initialize PAM authentication.

        Returns PAM_CONV_AGAIN with conversation messages in the reason field.
        Use auth_continue() to provide responses.
        """
        # Ensure no authentication is already in progress
        if self._thread_state or self._auth_thread:
            raise RuntimeError("Authentication already in progress")

        self.check_stage(AuthenticatorStage.START)

        # Create thread communication state with all PAM parameters
        self._thread_state = ConversationThreadState(
            main_thread_id=threading.current_thread().ident,
            input_queue=queue.Queue(),
            output_queue=queue.Queue(),
            done_event=threading.Event(),
            service_name=self.state.service,
            user=self.username,
            conversation_function=_conv_callback,
            rhost=self.rhost,
            ruser=self.ruser,
            fail_delay=self.fail_delay if self.fail_delay is not None else 0,
            pam_env=self.pam_env
        )

        # Start authentication thread with module-level worker function
        self._auth_thread = threading.Thread(
            target=_auth_thread_worker,
            args=(self._thread_state,),
        )
        self._auth_thread.start()

        self.state.stage = AuthenticatorStage.AUTH

        return self._wait_for_auth_result()

    def auth_continue(self, responses: List[Optional[str]]) -> AuthenticatorResponse:
        """
        Continue authentication by providing responses to conversation messages.

        Args:
            responses: List of responses for the conversation messages.
                      Use None for messages that don't need a response.
        """
        if self.state.stage != AuthenticatorStage.AUTH:
            raise RuntimeError(f"Not in AUTH stage (current: {self.state.stage})")

        if not self._thread_state or not self._auth_thread:
            raise RuntimeError("No authentication in progress")

        # Send responses to auth thread
        self._thread_state.input_queue.put(responses)

        return self._wait_for_auth_result()

    def account_management(self) -> AuthenticatorResponse:
        self.check_stage(AuthenticatorStage.LOGIN)

        if not self.ctx:
            raise RuntimeError(
                "No PAM context available - authentication may not have completed"
            )

        try:
            self.ctx.acct_mgmt()
            code = truenas_pypam.PAMCode.PAM_SUCCESS
            reason = None
        except truenas_pypam.PAMError as e:
            code = e.code
            reason = str(e)

        # The account management and authentication stages blend together in some
        # modules and so we keep it as same stage
        return AuthenticatorResponse(AuthenticatorStage.AUTH, code, reason)

    def open_session(self) -> AuthenticatorResponse:
        """Open PAM session."""
        self.check_stage(AuthenticatorStage.LOGIN)

        if not self.ctx:
            raise RuntimeError(
                "No PAM context available - authentication may not have completed"
            )

        try:
            self.ctx.open_session()
            code = truenas_pypam.PAMCode.PAM_SUCCESS
            reason = None
        except truenas_pypam.PAMError as e:
            code = e.code
            reason = str(e)

        return AuthenticatorResponse(AuthenticatorStage.OPEN_SESSION, code, reason)

    def close_session(self) -> AuthenticatorResponse:
        """Close PAM session."""
        self.check_stage(AuthenticatorStage.LOGOUT)

        if not self.ctx:
            raise RuntimeError("No PAM context available")

        try:
            self.ctx.close_session()
            code = truenas_pypam.PAMCode.PAM_SUCCESS
            reason = None
        except truenas_pypam.PAMError as e:
            code = e.code
            reason = str(e)

        return AuthenticatorResponse(AuthenticatorStage.CLOSE_SESSION, code, reason)

    def end(self) -> None:
        """Clean up PAM context and reset state."""
        # Cancel any ongoing authentication
        if self._thread_state:
            self._thread_state.done_event.set()
            if self._auth_thread and self._auth_thread.is_alive():
                self._auth_thread.join(timeout=2.0)

            self._thread_state.input_queue.shutdown(immediate=True)
            self._thread_state.output_queue.shutdown(immediate=True)
            self._thread_state.pam_context = None

        # Reset state
        self.state = AuthenticatorState(service=self.state.service)
        self.ctx = None
        self._thread_state = None
        self._auth_thread = None

    def login(self) -> AuthenticatorResponse:
        """Perform login operations including opening session."""
        self.check_stage(AuthenticatorStage.LOGIN)

        resp = self.open_session()
        if resp.code != truenas_pypam.PAMCode.PAM_SUCCESS:
            self.end()
            return resp

        self.state.login_at = datetime.now(UTC)
        self.state.stage = AuthenticatorStage.LOGOUT

        return AuthenticatorResponse(
            AuthenticatorStage.LOGIN,
            truenas_pypam.PAMCode.PAM_SUCCESS,
            None
        )

    def logout(self) -> AuthenticatorResponse:
        """Perform logout operations including closing session."""
        self.check_stage(AuthenticatorStage.LOGOUT)

        # Close the PAM session
        resp = self.close_session()

        # Clean up
        self.end()

        return AuthenticatorResponse(AuthenticatorStage.LOGOUT, resp.code, resp.reason)

    @property
    def login_at(self) -> datetime:
        """Return the login timestamp."""
        return self.state.login_at

    def __del__(self):
        if self.state.stage is AuthenticatorStage.LOGOUT:
            try:
                self.logout()
            except Exception:
                pass

        else:
            self.end()

        self.state = None


class SimpleAuthenticator(UserPamAuthenticator):
    """Simple authenticator with basic username/password authentication."""
    def __init__(self, **kwargs):
        self.password = kwargs.pop('password', '')
        super().__init__(**kwargs)

    def auth_init(self) -> AuthenticatorResponse:
        """ Perform simple username / password authentication with credentials
        provided in the init method """
        self.check_stage(AuthenticatorStage.START)

        pam_ctx_args = {
            'user': self.username,
            'conversation_function': _conv_callback_simple,
            # Pass thread_state as private data
            'conversation_private_data': {
                'username': self.username,
                'password': self.password
            },
            'service_name': self.state.service
        }

        if self.rhost is not None:
            pam_ctx_args['rhost'] = self.rhost
        if self.ruser is not None:
            pam_ctx_args['ruser'] = self.ruser
        if self.fail_delay:
            pam_ctx_args['fail_delay'] = self.fail_delay

        ctx = truenas_pypam.get_context(**pam_ctx_args)

        if self.pam_env:
            for key, value in self.pam_env.items():
                ctx.set_env(name=key, value=value)

        try:
            ctx.authenticate()
        except Exception as exc:
            reason = str(exc)
            if isinstance(exc, truenas_pypam.PAMError):
                code = exc.code
            else:
                code = truenas_pypam.PAMCode.PAM_SYSTEM_ERR

            return AuthenticatorResponse(AuthenticatorStage.AUTH, code, reason)
        finally:
            self.password = None

        self.ctx = ctx
        self.state.stage = AuthenticatorStage.LOGIN

        user_info = {
            'pw_name': self.username,
            'account_attributes': []
        }

        return AuthenticatorResponse(
            stage=AuthenticatorStage.AUTH,
            code=truenas_pypam.PAMCode.PAM_SUCCESS,
            reason=None,
            user_info = user_info
        )

    def auth_continue(self) ->AuthenticatorResponse:
        raise NotImplementedError

    def authenticate_simple(self) -> bool:
        """
        Simple authentication that automatically handles password prompts.
        Returns True/False.
        """
        resp = self.auth_init()
        return resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
