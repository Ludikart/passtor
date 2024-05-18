from setuptools import setup

setup(
    name='PasstorServer',
    version='1.0',
    py_modules=['passtorserver'],
    install_requires=['argon2-cffi', 'pycryptodome', 'flask',],
)
