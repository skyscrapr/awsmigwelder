""" setup.py """

from setuptools import setup, find_packages

setup(
    name='awsmigwelder',
    version='0.1.0',
    description='Tooling to export and consolidate AWS security group rules from discovery data to support migrations.',
    author='Richard Weerasinghe',
    author_email='richard@skyscrapr.io',
    packages=find_packages(),
    install_requires=[
        "boto3==1.38.29",
        "botocore==1.38.29",
        "certifi==2025.4.26",
        "charset-normalizer==3.4.2",
        "idna==3.10",
        "jmespath==1.0.1",
        "python-dateutil==2.9.0.post0",
        "requests==2.32.3",
        "s3transfer==0.13.0",
        "six==1.17.0",
        "urllib3==2.4.0"
    ],
    python_requires=">=3.8"
)