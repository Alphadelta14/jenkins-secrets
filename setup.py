#!/usr/bin/env python
"""
Jenkins Secrets

Author: Alphadelta14 <alpha@alphaservcomputing.solutions>

"""

from setuptools import setup, find_packages

__version__ = '0.1.0'

setup(
    name='jenkins-secrets',
    version=__version__,
    description='Jenkins Secrets',
    url='https://github.com/Alphadelta14/jenkins-secrets',
    author='Alphadelta14',
    author_email='alpha@alphaservcomputing.solutions',
    license='MIT',
    install_requires=[
        'cryptography',
    ],
    entry_points={
        'console_scripts': [],
    },
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ]
)
