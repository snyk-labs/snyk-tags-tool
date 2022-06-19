from setuptools import setup

setup(
    name='snyk_tags',
    version='0.1.0',    
    description='Tool designed to add tags in bulk to Snyk projects',
    url='https://github.com/EricFernandezSnyk/snyk-tags-tool',
    author='Eric Fernandez',
    author_email='eric.fernandez@snyk.io',
    license='MIT',
    packages=['snyk_tags'],
    install_requires=['httpx',
                      'python-dotenv',                     
                      ],

    classifiers=[
        'Development Status :: 1 - Planning',
        'License :: OSI Approved :: MIT',  
        'Operating System :: POSIX :: Linux',        
        'Programming Language :: Python :: 3.6',
    ],
)