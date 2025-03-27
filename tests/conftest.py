import pytest
import requests
import tempfile
import shutil
import glob


def concatenate_files(input_files, output_file):
    with open(output_file, 'w') as outfile:
        for file_name in input_files:
            with open(file_name, 'r') as infile:
                outfile.write(infile.read())
                # outfile.write("\n")


def download_file(url, destination_path):
    response = requests.get(url, stream=True)
    # Check if the request was successful
    if response.status_code == 200:
        # Open the destination file in write-binary mode
        with open(destination_path, 'wb') as f:
            # Write the content of the response to the file in chunks
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
    else:
        raise Exception(
            f"Failed to download file. Status code: {response.status_code}")


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
def certificates():
    cert_path = "https://dl.igtf.net/distribution/igtf/current/" \
        "igtf-policy-installation-bundle-1.134.tar.gz"
    with tempfile.TemporaryDirectory() as temp_dir:
        destination_path = temp_dir + '/cert.tgz'
        output_file = temp_dir + '/cert.pep'
        download_file(cert_path, destination_path)
        shutil.unpack_archive(destination_path, temp_dir, format='gztar')
        concatenate_files(glob.glob(temp_dir +
                                    '/igtf-policy-installation-bundle-1.134/src/accredited/*.pem'),
                          output_file)
        yield output_file
