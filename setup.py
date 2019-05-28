#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Filename: setup.py
import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

with open('LICENSE', 'r') as fh:
    license = fh.read()

setuptools.setup(

    # Package information
    name='moxie', # Package name
    version='0.1.0', # Package version
    description='A stateful session wrapper for python requests',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license=license,
    classifiers=[
        'Programming Language :: Python :: 3',
        #'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],

    # Package definitions and requirements
    packages=setuptools.find_packages(),
    install_requires=[
        'requests',
        'requests-toolbelt'
    ],

    # Contact information
    author='Taylor Fox Dahlin',
    author_email='tfdahlin@gmail.com',
    url='', # GITHUB URL GOES HERE -- personal github or 2uinc?

    # Tests
    test_suite='nose.collector',
    tests_require=['nose'],

    # Miscellaneous
    zip_safe=False,
)
