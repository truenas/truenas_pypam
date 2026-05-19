# TrueNAS Python PAM authenticator
#
# NOTE: this module is currently WIP pending a truenas NSS
# wrapper that will furnish account details and finalized
# work on pam_truenas.

from __future__ import annotations

import enum
import truenas_pypam
from dataclasses import dataclass
from datetime import datetime, UTC
from typing import Optional, Sequence, Any


class AuthenticatorStage(enum.StrEnum):
    START = 'START'
    AUTH = 'AUTH'
    OPEN_SESSION = 'OPEN_SESSION'
    CLOSE_SESSION = 'CLOSE_SESSION'
    LOGIN = 'LOGIN'
    LOGOUT = 'LOGOUT'


@dataclass(slots=True)
class AuthenticatorState:
    service: str = 'login'
    """ pam service name to be used for handle. """
    stage: AuthenticatorStage = AuthenticatorStage.START
    """ Stage of PAM session / conversation. """
    otpw_possible: bool = False
    """ The authenticator supports authentication using single-use passwords. """
    login_at: datetime | None = None
    """ Time at which session performed actual login """
    passwd: dict[str, Any] | None = None
    """ passwd dict entry for user """
    messages: list[Any] | None = None
    """ Messages received during PAM conversation """


@dataclass(slots=True)
class AuthenticatorResponse[T = dict[str, Any]]:
    stage: AuthenticatorStage
    code: truenas_pypam.PAMCode  # PAM response code
    # reason for non-success OR conversation messages when PAM_CONV_AGAIN
    reason: Any
    # passwd dict (only populated on authenticate calls)
    user_info: T | None = None


def _conv_callback_simple(
    ctx: truenas_pypam.PamContext,
    messages: tuple[truenas_pypam.struct_pam_message, ...],
    private_data: Any,
) -> list[str | None]:
    reply: list[str | None] = []
    for m in messages:
        if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            resp = private_data['password']
        elif m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_ON:
            resp = private_data['username']
        else:
            resp = None

        reply.append(resp)

    return reply


class UserPamAuthenticator[T = dict[str, Any]]:
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
        self.dbid = 0
        self.ctx: truenas_pypam.PamContext | None = None

    def check_stage(self, expected: AuthenticatorStage) -> None:
        if self.state.stage is not expected:
            raise RuntimeError(
                f'{self.state.stage}: unexpected authenticator run state. '
                f'Expected: {expected}'
            )

    def _handle_auth_result(
        self,
        result: tuple[truenas_pypam.struct_pam_message, ...] | None,
    ) -> AuthenticatorResponse[T]:
        if result is not None:
            return AuthenticatorResponse(AuthenticatorStage.AUTH,
                                         truenas_pypam.PAMCode.PAM_CONV_AGAIN, result)
        self.state.stage = AuthenticatorStage.LOGIN
        user_info = {'pw_name': self.username, 'account_attributes': []}
        return AuthenticatorResponse(AuthenticatorStage.AUTH, truenas_pypam.PAMCode.PAM_SUCCESS,
                                     None, user_info)  # type: ignore[arg-type]

    def auth_init(self) -> AuthenticatorResponse[T]:
        """
        Initialize PAM authentication.

        Returns PAM_CONV_AGAIN with conversation messages in the reason field.
        Use auth_continue() to provide responses.
        """
        if self.ctx is not None:
            raise RuntimeError("Authentication already in progress")

        self.check_stage(AuthenticatorStage.START)

        username = f'{self.username}:{self.dbid}' if self.dbid else self.username
        ctx_args: dict[str, Any] = {'user': username, 'service_name': self.state.service}
        if self.rhost is not None:
            ctx_args['rhost'] = self.rhost
        if self.ruser is not None:
            ctx_args['ruser'] = self.ruser
        if self.fail_delay is not None:
            ctx_args['fail_delay'] = self.fail_delay

        self.ctx = truenas_pypam.get_context(**ctx_args)
        for key, value in self.pam_env.items():
            self.ctx.set_env(name=key, value=value)

        self.state.stage = AuthenticatorStage.AUTH

        try:
            result = self.ctx.begin_authentication(timeout=self.authentication_timeout)
        except TimeoutError:
            self.end()
            return AuthenticatorResponse(AuthenticatorStage.AUTH, truenas_pypam.PAMCode.PAM_SYSTEM_ERR,
                                         f"Authentication timeout after {self.authentication_timeout} seconds")
        except truenas_pypam.PAMError as e:
            if not self.state.otpw_possible:
                self.end()
            return AuthenticatorResponse(AuthenticatorStage.AUTH, truenas_pypam.PAMCode(e.code), str(e))

        return self._handle_auth_result(result)

    def auth_continue(self, responses: Sequence[Optional[str]]) -> AuthenticatorResponse[T]:
        """
        Continue authentication by providing responses to conversation messages.

        Args:
            responses: List of responses for the conversation messages.
                      Use None for messages that don't need a response.
        """
        if self.state.stage != AuthenticatorStage.AUTH:
            raise RuntimeError(f"Not in AUTH stage (current: {self.state.stage})")
        if self.ctx is None:
            raise RuntimeError("No authentication in progress")

        try:
            result = self.ctx.continue_authentication(responses, timeout=self.authentication_timeout)
        except TimeoutError:
            self.end()
            return AuthenticatorResponse(AuthenticatorStage.AUTH, truenas_pypam.PAMCode.PAM_SYSTEM_ERR,
                                         f"Authentication timeout after {self.authentication_timeout} seconds")
        except truenas_pypam.PAMError as e:
            if not self.state.otpw_possible:
                self.end()
            return AuthenticatorResponse(AuthenticatorStage.AUTH, truenas_pypam.PAMCode(e.code), str(e))

        return self._handle_auth_result(result)

    def account_management(self) -> AuthenticatorResponse[T]:
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
            code = truenas_pypam.PAMCode(e.code)
            reason = str(e)

        # The account management and authentication stages blend together in some
        # modules and so we keep it as same stage
        return AuthenticatorResponse(AuthenticatorStage.AUTH, code, reason)

    def open_session(self) -> AuthenticatorResponse[T]:
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
            code = truenas_pypam.PAMCode(e.code)
            reason = str(e)

        return AuthenticatorResponse(AuthenticatorStage.OPEN_SESSION, code, reason)

    def close_session(self) -> AuthenticatorResponse[T]:
        """Close PAM session."""
        self.check_stage(AuthenticatorStage.LOGOUT)

        if not self.ctx:
            raise RuntimeError("No PAM context available")

        try:
            self.ctx.close_session()
            code = truenas_pypam.PAMCode.PAM_SUCCESS
            reason = None
        except truenas_pypam.PAMError as e:
            code = truenas_pypam.PAMCode(e.code)
            reason = str(e)

        return AuthenticatorResponse(AuthenticatorStage.CLOSE_SESSION, code, reason)

    def end(self) -> None:
        self.ctx = None   # dealloc cancels any pending C auth thread
        self.state = AuthenticatorState(service=self.state.service)

    def login(self) -> AuthenticatorResponse[T]:
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

    def logout(self) -> AuthenticatorResponse[T]:
        """Perform logout operations including closing session."""
        self.check_stage(AuthenticatorStage.LOGOUT)

        # Close the PAM session
        resp = self.close_session()

        # Clean up
        self.end()

        return AuthenticatorResponse(AuthenticatorStage.LOGOUT, resp.code, resp.reason)

    @property
    def login_at(self) -> datetime | None:
        """Return the login timestamp."""
        return self.state.login_at

    def __del__(self) -> None:
        if self.state.stage is AuthenticatorStage.LOGOUT:
            try:
                self.logout()
            except Exception:
                pass

        else:
            self.end()


class SimpleAuthenticator(UserPamAuthenticator):
    """Simple authenticator with basic username/password authentication."""
    def __init__(self, **kwargs: Any) -> None:
        self.password = kwargs.pop('password', '')
        super().__init__(**kwargs)

    def auth_init(self) -> AuthenticatorResponse:
        """ Perform simple username / password authentication with credentials
        provided in the init method """
        self.check_stage(AuthenticatorStage.START)

        pam_ctx_args: dict[str, Any] = {
            'user': self.username,
            'conversation_function': _conv_callback_simple,
            'conversation_private_data': {'username': self.username, 'password': self.password},
            'service_name': self.state.service,
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

        code: truenas_pypam.PAMCode = truenas_pypam.PAMCode.PAM_SYSTEM_ERR
        try:
            ctx.authenticate()
        except Exception as exc:
            reason = str(exc)
            if isinstance(exc, truenas_pypam.PAMError):
                code = truenas_pypam.PAMCode(exc.code)
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
            user_info=user_info
        )

    def auth_continue(self, responses: Sequence[str | None]) -> AuthenticatorResponse:
        raise NotImplementedError

    def authenticate_simple(self) -> bool:
        """
        Simple authentication that automatically handles password prompts.
        Returns True/False.
        """
        resp = self.auth_init()
        return resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
