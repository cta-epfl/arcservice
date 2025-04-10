from typing import Any
import os
import io

from arcservice.app import (stream_file_stats, filelist_metrics,
                            refresh_oidc_token)


def test_refresh_oidc_token(mock):
    token_url = "https://keycloak.cta.cscs.ch/realms/master/protocol" \
        "/openid-connect/token"
    access_token = "access_token"
    refresh_token = "refresh_token"

    os.environ['DCACHE_REFRESH_TOKEN'] = 'token'
    os.environ['DCACHE_CLIENT_SECRET'] = 'secret'
    mock.post(token_url,
              json={"access_token": access_token,
                    refresh_token: refresh_token})
    new_access_token = refresh_oidc_token()

    assert os.environ['DCACHE_REFRESH_TOKEN'] == refresh_token
    assert new_access_token == access_token


def test_filestat(mock):
    token_url = "https://keycloak.cta.cscs.ch/realms/master/protocol" \
        "/openid-connect/token"
    access_token = "access_token"
    refresh_token = "refresh_token"

    os.environ['DCACHE_REFRESH_TOKEN'] = 'token'
    os.environ['DCACHE_CLIENT_SECRET'] = 'secret'
    mock.post(token_url,
              json={"access_token": access_token,
                    refresh_token: refresh_token})

    dcache_url = 'https://dcache-dev.ctaodc.ch:2880'
    file_url = dcache_url + "/pnfs/cta.cscs.ch/filelists/latest"
    os.environ['DCACHE_URL'] = dcache_url

    # Create a string buffer
    buffer = io.StringIO()
    buffer.write("isum,ipnfsid,path,isize,ictime,imtime,iatime,icrtime")
    for path_group in ['lst', 'cta', 'dteam', 'another']:
        for _ in range(10):
            buffer.write(f"413984,695984,/pnfs/cta.cscs.ch/{path_group}/"
                         "673936,637640,2023-02-20 12:37:04.325,2023-02-20 "
                         "12:37:04.325,2023-02-20 12:37:04.18,2023-02-20 "
                         "12:37:04.18")

    mock.get(file_url, content=str(buffer))
    lines = stream_file_stats()
    print(filelist_metrics(lines))
