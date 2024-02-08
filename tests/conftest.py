import pytest
import tempfile


@pytest.fixture(scope="session")
def app():
    from arcservice.app import app
    app.config.update({
        "TESTING": True,
        "DEBUG": True,
        "SERVER_NAME": 'app',
    })

    yield app
