import pytest
import requests_mock

@pytest.fixture(scope="session")
def app():
    from arcservice.app import app
    app.config.update({
        "TESTING": True,
        "DEBUG": True,
        "SERVER_NAME": 'app',
    })

    yield app


@pytest.fixture(scope="session")
def mock():
    with requests_mock.Mocker() as mock:
        yield mock
