#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

install_requires = [
    'sentry==9.1.2',
]

setup(
    name='sentry-dingtalk4',
    version='1.0.0',
    keywords='sentry dingding dingtalk',
    author='AdamWang',
    author_email='wangbinhan@xiaoduotech.com',
    url='https://github.com/AdamWangDoggie/sentry-dingtalk',
    description='A Sentry extension which integrates with Dingtalk robot(Dingtalk version>=4.7.15).',
    long_description=__doc__,
    long_description_content_type='text/markdown',
    license='BSD',
    platforms='any',
    packages=find_packages(),
    zip_safe=False,
    install_requires=install_requires,
    entry_points={
        'sentry.plugins': [
            'dingtalk = sentry_dingtalk.plugin:DingtalkPlugin4'
        ],
    },
    include_package_data=True,
    classifiers=[
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Topic :: Software Development'
    ],
)
