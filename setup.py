from setuptools import setup, find_packages

setup(
    name="code-review-agent",
    version="1.0.0",
    description="Intelligent automated code review system with multi-agent orchestration",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "PyGithub>=2.1.0",
        "fastapi>=0.115.0",
        "uvicorn[standard]>=0.30.0",
        "openai>=1.12.0",
        "pyyaml>=6.0.1",
        "python-dotenv>=1.0.0",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "review-agent=src.review_agent:main",
            "review-webhook=src.webhook_server:main",
        ],
    },
)
