from setuptools import setup, find_packages
setup(
    name='srcf-wls',
    version='0.1.0',
    author="Edwin Bahrami Balani",
    author_email="eb677@srcf.net",
    license="MIT",
    description="SRCF Goose web login service",
    url="https://github.com/srcf/goose",
    packages=find_packages(exclude=["tests"]),
    install_requires=[
        'ucam-wls',
        'Flask',
    ],
    python_requires='>=3',
)
