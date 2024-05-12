import setuptools

with open("README.md") as f:
    long_description = f.read()


with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="wconsole_extractor",
    version="1.0.1",
    description="",
    url="https://github.com/Ruulian/wconsole_extractor",
    author="Ruulian",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author_email="ruulian@protonmail.com",
    packages=setuptools.find_packages(),
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=requirements
)
