from setuptools import setup, find_packages


requires = [
    'plaster_pastedeploy',
    'pyramid >= 1.9a',
    'pyramid_debugtoolbar',
    'pyramid_jinja2',
    'pyramid_retry',
    'pyramid_tm',
    'SQLAlchemy',
    'transaction',
    'zope.sqlalchemy',
    'waitress',
    'psycopg2',
    'passlib'
]

tests_require = [
    'WebTest >= 1.3.1',  # py3 compat
    'pytest',
    'pytest-cov',
    'Faker'
]

dev_requires = [
    'ipython',
    'pyramid_ipython'
]

setup(
    name='pyramid_todo',
    version='0.0',
    description='pyramid_todo',
    classifiers=[
        'Programming Language :: Python',
        'Framework :: Pyramid',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
    ],
    author='Nicholas Hunt-Walker',
    author_email='nhuntwalker@gmail.com',
    url='',
    keywords='web pyramid pylons',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    extras_require={
        'testing': tests_require,
        'dev': dev_requires
    },
    install_requires=requires,
    entry_points={
        'paste.app_factory': [
            'main = pyramid_todo:main',
        ],
        'console_scripts': [
            'initdb = pyramid_todo.scripts.initializedb:main',
        ],
    },
)
