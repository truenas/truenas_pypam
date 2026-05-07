import enum
from collections.abc import Callable, Sequence
from typing import ClassVar, final, type_check_only


@type_check_only
@final
class struct_pam_message(tuple[MSGStyle, str]):
    n_fields: ClassVar[int]
    n_sequence_fields: ClassVar[int]
    n_unnamed_fields: ClassVar[int]
    @property
    def msg_style(self) -> MSGStyle: ...
    @property
    def msg(self) -> str: ...


@type_check_only
@final
class PamContext:
    user: str | None
    ruser: str | None
    rhost: str | None
    def authenticate(self, *, silent: bool = ..., disallow_null_authtok: bool = ...) -> None: ...
    def begin_authentication(self, *, silent: bool = ..., disallow_null_authtok: bool = ..., timeout: int = ...) -> tuple[struct_pam_message, ...] | None: ...
    def continue_authentication(self, responses: Sequence[str | None], *, timeout: int = ...) -> tuple[struct_pam_message, ...] | None: ...
    def acct_mgmt(self, *, silent: bool = ..., disallow_null_authtok: bool = ...) -> None: ...
    def chauthtok(self, *, silent: bool = ..., change_expired_authtok: bool = ...) -> None: ...
    def open_session(self, *, silent: bool = ...) -> None: ...
    def close_session(self, *, silent: bool = ...) -> None: ...
    def setcred(self, *, operation: CredOp, silent: bool = ...) -> None: ...
    def get_env(self, name: str) -> str: ...
    def set_env(self, *, name: str, value: str | None = ..., readonly: bool = ...) -> None: ...
    def env_dict(self) -> dict[str, str]: ...
    def messages(self) -> tuple[tuple[struct_pam_message, ...], ...]: ...
    def set_conversation(self, *, conversation_function: Callable[[PamContext, tuple[struct_pam_message, ...], object], Sequence[str | None]]) -> None: ...


class PAMCode(enum.IntEnum):
    PAM_SUCCESS = 0
    PAM_OPEN_ERR = 1
    PAM_SYMBOL_ERR = 2
    PAM_SERVICE_ERR = 3
    PAM_SYSTEM_ERR = 4
    PAM_BUF_ERR = 5
    PAM_PERM_DENIED = 6
    PAM_AUTH_ERR = 7
    PAM_CRED_INSUFFICIENT = 8
    PAM_AUTHINFO_UNAVAIL = 9
    PAM_USER_UNKNOWN = 10
    PAM_MAXTRIES = 11
    PAM_NEW_AUTHTOK_REQD = 12
    PAM_ACCT_EXPIRED = 13
    PAM_SESSION_ERR = 14
    PAM_CRED_UNAVAIL = 15
    PAM_CRED_EXPIRED = 16
    PAM_CRED_ERR = 17
    PAM_NO_MODULE_DATA = 18
    PAM_CONV_ERR = 19
    PAM_AUTHTOK_ERR = 20
    PAM_AUTHTOK_RECOVERY_ERR = 21
    PAM_AUTHTOK_LOCK_BUSY = 22
    PAM_AUTHTOK_DISABLE_AGING = 23
    PAM_TRY_AGAIN = 24
    PAM_IGNORE = 25
    PAM_ABORT = 26
    PAM_AUTHTOK_EXPIRED = 27
    PAM_MODULE_UNKNOWN = 28
    PAM_BAD_ITEM = 29
    PAM_CONV_AGAIN = 30
    PAM_INCOMPLETE = 31


class MSGStyle(enum.IntEnum):
    PAM_PROMPT_ECHO_OFF = ...
    PAM_PROMPT_ECHO_ON = ...
    PAM_ERROR_MSG = ...
    PAM_TEXT_INFO = ...


class CredOp(enum.IntEnum):
    PAM_ESTABLISH_CRED = ...
    PAM_DELETE_CRED = ...
    PAM_REINITIALIZE_CRED = ...
    PAM_REFRESH_CRED = ...


class PAMError(RuntimeError):
    code: PAMCode
    name: str
    err_str: str
    message: str
    location: str


def get_context(
    *,
    service_name: str = ...,
    user: str,
    conversation_function: Callable[[PamContext, tuple[struct_pam_message, ...], object], Sequence[str | None]] | None = ...,
    conversation_private_data: object = ...,
    confdir: str | None = ...,
    rhost: str | None = ...,
    ruser: str | None = ...,
    fail_delay: int = ...,
) -> PamContext: ...
