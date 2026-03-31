from setuptools import setup, find_packages

setup(
    name="guni",
    version="2.2.0",
    packages=find_packages(),
    install_requires=[
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "fastapi>=0.110.0",
        "gunicorn>=21.2.0",
        "uvicorn[standard]>=0.27.0",
        "pydantic>=2.0.0",
        "httpx>=0.27.0",
        "python-dotenv>=1.0.0",
        "aiofiles>=23.0.0",
        "pymongo>=4.16.0",
        "mongomock>=4.3.0",
    ],
    python_requires=">=3.11",
)
