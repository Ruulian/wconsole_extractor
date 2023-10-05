import setuptools

long_description = "WConsole Extractor is a python library which automatically exploits a Werkzeug development server in debug mode. You just have to write a python function that leaks a file content and you have your shell :)"

setuptools.setup(
    name="wconsole_extractor",
    version="1.0",
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
    ]
)