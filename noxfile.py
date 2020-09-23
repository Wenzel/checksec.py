import nox

nox.options.sessions = ["lint", "fmt"]


@nox.session
def lint(session):
    session.install("flake8==3.8.3", "flake8-bugbear==20.1.4", "isort==5.5.3")
    session.run("flake8", "--show-source", "--statistics")
    session.run("isort", "--line-length", "120", ".")


@nox.session
def fmt(session):
    session.install("black==20.8b1")
    session.run("black", "--line-length", "120", ".")


@nox.session
def type(session):
    session.install("-r", "requirements.txt")
    session.install("mypy==0.782")
    session.run("mypy", ".")
