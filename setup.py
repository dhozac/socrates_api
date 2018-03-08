#!/usr/bin/env python

from setuptools import setup
import os
import re

setup(name='socrates_api',
      version='1.0.0',
      license='Apache Software License',
      description='Source of Truth for hardware, virtual machines, and networks',
      author='Klarna Bank AB',
      author_email='core-platform@klarna.com',
      url='',
      packages=['socrates_api', 'socrates_api.migrations', 'socrates_api.templatetags'],
      install_requires=map(lambda x: re.sub(r".*#egg=(.*)", lambda m: m.group(1), x.strip()), open(os.path.join(os.path.dirname(__file__), 'requirements.txt')).readlines()),
      include_package_data=True,
      zip_safe=False,
      classifiers=[
          'Development Status :: 7 - Inactive',
          'Environment :: Web Environment',
          'Framework :: Django :: 1.11',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: Apache Software License',
          'Topic :: System :: Installation/Setup',
      ],
     )
