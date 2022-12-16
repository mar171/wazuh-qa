# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from setuptools import setup, find_namespace_packages
import shutil
import glob


setup(
    name='wazuh-qa-framework',
    version='1.0.0',
    description='Wazuh testing utilities to help programmers automate tests',
    url='https://github.com/wazuh/wazuh-qa',
    author='Wazuh',
    author_email='hello@wazuh.com',
    license='GPLv2',
    package_dir={'': 'src'},
    packages=find_namespace_packages(where='src'),
    # package_data={'wazuh_testing': package_data_list},
    # include_package_data=True,
    zip_safe=False
)

# Clean build files
shutil.rmtree('dist')
shutil.rmtree('build')
shutil.rmtree(glob.glob('src/*.egg-info')[0])

