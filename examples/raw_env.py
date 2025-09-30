import truenas_pypam


# callback stub to allow initializing pam context
def callback_not_implemented(ctx, messages, private_data):
    raise ValueError("Shouldn't be called")


ctx = truenas_pypam.get_context(user='bob', conversation_function=callback_not_implemented)

# basic get-set
ctx.set_env(name='CANARY', value='FOO')
assert ctx.get_env(name='CANARY') == 'FOO'

# removal
ctx.set_env(name='CANARY')
try:
    ctx.get_env(name='CANARY')
except FileNotFoundError:
    pass
else:
    raise FileExistsError('environmental variable not deleted')


# now get enviroment dict
ctx.set_env(name='CANARY', value='FOO3')
pam_env = ctx.env_dict()
assert 'CANARY' in pam_env

assert pam_env['CANARY'] == 'FOO3'
