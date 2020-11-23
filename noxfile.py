import nox

nox.options.sessions = ["fmt", "lint", "test_e2e"]


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


@nox.session
def run(session):
    args = session.posargs
    session.install("-r", "requirements.txt")
    session.run("python", "-m", "checksec", *args)


@nox.session
def test_unit(session):
    # run unit tests
    args = session.posargs
    session.install("-r", "requirements.txt")
    session.install("pytest==6.0.2", "coverage==5.3")
    session.run("coverage", "run", "-m", "pytest", "-v", "-k", "unit", *args)


@nox.session
def test_e2e(session):
    args = session.posargs
    session.install(".")
    session.install("pytest==6.0.2", "coverage==5.3")
    session.run("coverage", "run", "-m", "pytest", "-v", "-k", "e2e", *args)
