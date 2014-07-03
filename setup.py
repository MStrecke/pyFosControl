from setuptools import setup, find_packages

DESCRIPTION = "Python interface to Foscam CGI API"

with open('README.md') as f:
    LONG_DESCRIPTION = f.read()

with open('requirements.txt') as f:
    required = f.read().splitlines()

VERSION = '0.1.1'

CLASSIFIERS = [
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU v2',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Topic :: Software Development :: Libraries :: Python Modules',
]

setup(name='foscontrol',
    version=VERSION,
    packages=find_packages(),
    install_requires=required,
    url='https://github.com/scragg0x/pyfoscontrol',
    license='GNU v2',
    include_package_data=True,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    platforms=['any'],
    classifiers=CLASSIFIERS,
    #test_suite='tests',
)