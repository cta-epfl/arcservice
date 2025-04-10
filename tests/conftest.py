import pytest
import requests_mock
import os


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
def access_token():
    yield "access_token"


@pytest.fixture(scope="session")
def refresh_token():
    yield "refresh_token"


@pytest.fixture(scope="session")
def mock(access_token, refresh_token):
    token_url = "https://keycloak.cta.cscs.ch/realms/master/protocol" \
        "/openid-connect/token"

    os.environ['DCACHE_REFRESH_TOKEN'] = 'token'
    os.environ['DCACHE_CLIENT_SECRET'] = 'secret'
    
    with requests_mock.Mocker() as mock:
        mock.post(token_url,
              json={"access_token": access_token,
                    refresh_token: refresh_token})
        yield mock
