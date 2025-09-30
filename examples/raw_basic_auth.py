import truenas_pypam


def callback_basic_auth(ctx, messages, private_data):
    """
    PAM conversation callback function.
    Handles PAM prompts by providing responses based on message style.
    """
    reply = []
    for m in messages:
        rep = None
        # PAM_PROMPT_ECHO_OFF (1) - typically password prompts
        if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            if 'Password' in m.msg:
                rep = private_data['password']
        # Could also handle other message styles:
        # PAM_PROMPT_ECHO_ON (2) - username prompts
        # PAM_ERROR_MSG (3) - error messages
        # PAM_TEXT_INFO (4) - informational text

        reply.append(rep)

    return reply


# Auth with correct password
data = {'password': 'Cats',}
ctx = truenas_pypam.get_context(user='bob',
                                conversation_function=callback_basic_auth,
                                conversation_private_data=data)
ctx.authenticate()


# Auth with incorrect password
data = {'password': 'Dogs',}
ctx = truenas_pypam.get_context(user='bob',
                                conversation_function=callback_basic_auth,
                                conversation_private_data=data)

try:
    ctx.authenticate()
except truenas_pypam.PAMError as exc:
    # Using the new PAMCode enum
    assert exc.code == truenas_pypam.PAMCode.PAM_AUTH_ERR
    assert exc.code.name == 'PAM_AUTH_ERR'
    assert exc.code.value == 7
    assert str(exc).startswith('[PAM_AUTH_ERR]')
    assert exc.message.startswith('pam_authenticate()')
    print(f"Authentication failed as expected: {exc.code.name}")
else:
    raise AssertionError("Expected authentication to fail!")
