from setuptools import setup, find_packages
import gostcrypto

with open('README.rst', 'r', encoding='utf-8') as readme_file:
    readme = readme_file.read()
with open('HISTORY.rst', 'r', encoding='utf-8') as history_file:
    history = history_file.read()

setup(
    name='gostcrypto',
    version = gostcrypto.__version__,
    description = 'GOST cryptographic functions',
    long_description = readme + '\n\n' + history,
    author = gostcrypto.__author__,
    author_email = gostcrypto.__author_email__,
    url='https://github.com/drobotun/gostcrypto',
    zip_safe=False,
    license=gostcrypto.__license__,
    keywords='cryptography, hash-functions, hmac, elliptic-curves, kuznechik, streebog, magma, block-cipher, cipher-algorithms, elliptic-curve-cryptography, pbkdf, gost-r-34-12-2015, gost-r-34-10-2012, gost-r-34-13-2015, gost-r-34-11-2012',
    project_urls={
        'Documentation': 'https://gostcrypto.readthedocs.io/',
        'Source': 'https://github.com/drobotun/gostcrypto'
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.8',
    ],
    test_suite="tests",
    packages=find_packages()
    )
