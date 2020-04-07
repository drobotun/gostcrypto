from setuptools import setup, find_packages
import gostcrypto

with open('README.rst', 'r', encoding='utf-8') as readme_file:
    readme = readme_file.read()
with open('HISTORY.rst', 'r', encoding='utf-8') as history_file:
    history = history_file.read()

setup(
    name='gostcrypto3',
    version = gostcrypto.__version__,
    description = 'GOST cryptographic functions',
    long_description = readme + '\n\n' + history,
    author = gostcrypto.__author__,
    author_email = gostcrypto.__author_email__,
    url='https://github.com/drobotun/gostcrypto',
    zip_safe=False,
    license=gostcrypto.__license__,
    keywords='cryptography, hash function, encryption, digital signature',
    project_urls={
        'Source': 'https://github.com/drobotun/gostcrypto'
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.7',
    ],
    test_suite="tests",
    packages=find_packages()
    )
