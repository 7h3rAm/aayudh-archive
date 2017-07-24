import os
from setuptools import setup, find_packages

setup(
  name = "aayudh",
  version = "0.1",
  author = "Ankur Tyagi (@7h3rAm)",
  author_email = "7h3rAm@gmail.com",
  description = ("Aayudh is the weaponary you need in your fight against evil."),
  license = "Creative Commons Attribution-Noncommercial-Share Alike license",
  keywords = "common utils methods lib",
  url = "https://github.com/7h3rAm/aayudh",
  packages = find_packages(),
  include_package_data = True,
  long_description = None,
  zip_safe = False,
  incstall_requires = [],
  classifiers = [
    "Development Status :: Alpha",
    "Topic :: Utilities",
    "License :: Creative Commons",
  ],
)
