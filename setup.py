try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
from litevault import __version__


setup(
    name='litevault',
    author='Garrett Berg',
    author_email='vitiral@gmail.com',
    version=__version__,
    py_modules=['litevault'],
    scripts=['bin/litevault'],
    license='MIT',
    install_requires=[
        'scrypt',
    ],
    description="lightweight password manager written in pure python",
    url="https://github.com/vitiral/litevault",
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Linux',
        'Programming Language :: Python :: 3',
        'Topic :: Utilities',
    ]
)
