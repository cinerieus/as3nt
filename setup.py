import setuptools

with open('README.md', 'r') as fh:
    long_desc = fh.read()

setuptools.setup(
        name = 'as3nt',
        version = '1.0.1',
        author = 'cinereus',
        author_email = 'cinereus@protonmail.com',
        description = 'Another Subdomain ENumeration Tool',
        long_description = long_desc,
        long_description_content_type="text/markdown",
        url = 'https://github.com/cinerieus/as3nt',
        packages = ['as3nt'],
        classifiers = [
            'Programming Language :: Python :: 3',
            'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
            'Operating System :: OS Independent',
            'Topic :: Security'
            ],
        entry_points = {
            'console_scripts': [
                'as3nt = as3nt.core:main',
                ],
            },
        install_requires = [
            'shodan',
            'tqdm',
            'dnspython',
            'ipwhois',
            'termcolor'
            ],
        python_requires = '>=3.6',
        )
