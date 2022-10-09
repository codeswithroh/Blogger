from setuptools import find_packages, setup

setup(
    name='flaskr',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True, #to include dirs like templates, static, etc. as described in Manifest.in file
    install_requires=[
        'flask'
    ],
)