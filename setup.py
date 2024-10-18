from setuptools import setup, find_packages

with open('requirements.txt', encoding='utf-16') as f:
    requirements = f.read().splitlines()

setup(
    name='policyweaver',
    version='0.1.0',
    description='A package to help you synchrnoize your data access policies with Fabric.',
    author='Christopher Price',
    author_email='chriprice@microsoft.com',
    url='https://github.com/microsoft/Policy-Weaver/',
    packages=find_packages(),
    install_requires=requirements,
    classifiers=[
        'Development Status :: 3 - Alpha',  # Choose the right status for your project
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',  # Or the license you use
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
    ],
    python_requires='>=3.8',  # Specify the Python version requirement
    package_data={
        'policyweaver': ['policyweaver.png'],
    },
)
