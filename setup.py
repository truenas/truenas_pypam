from setuptools import setup, Extension, find_packages

truenas_pypam_ext = Extension(
    'truenas_pypam',
    sources=[
        'src/ext/truenas_pypam.c',
        'src/ext/py_acct_mgmt.c',
        'src/ext/py_auth_thread.c',
        'src/ext/py_auth.c',
        'src/ext/py_chauthtok.c',
        'src/ext/py_ctx.c',
        'src/ext/py_conv.c',
        'src/ext/py_cred.c',
        'src/ext/py_env.c',
        'src/ext/py_error.c',
        'src/ext/py_session.c',
    ],
    include_dirs=['src/ext'],
    libraries=['pam', 'pam_misc', 'bsd']
)

setup(
    packages=['truenas_authenticator', 'truenas_pypam'],
    package_dir={
        'truenas_authenticator': 'src/truenas_authenticator',
        'truenas_pypam': 'stubs',
    },
    package_data={
        'truenas_authenticator': ['py.typed'],
        'truenas_pypam': ['*.pyi', 'py.typed'],
    },
    ext_modules=[truenas_pypam_ext]
)
