import os
import io

from arcservice.app import (stream_file_stats, filelist_metrics,
                            refresh_oidc_token)


# def test_refresh_oidc_token(mock, access_token, refresh_token):
#     new_access_token = refresh_oidc_token()

#     assert os.environ['DCACHE_REFRESH_TOKEN'] == refresh_token
#     assert new_access_token == access_token


def test_filestat(mock):
    dcache_url = 'https://dcache-dev.ctaodc.ch:2880'
    file_url = dcache_url + "/pnfs/cta.cscs.ch/filelists/latest"
    os.environ['DCACHE_URL'] = dcache_url

    # Create a string buffer
    buffer = io.StringIO()
    buffer.write("isum,ipnfsid,path,isize,ictime,imtime,iatime,icrtime\n")
    file_size = 6376495
    n_files = 10
    for path_group in ['lst', 'cta', 'another', 'lst/1', 'lst/1/2']:
        for i in range(n_files):
            buffer.write(f"413984,695984,/pnfs/cta.cscs.ch/{path_group}/f{i},"
                         f"{file_size},2023-02-20 12:37:04.325,2023-02-20 "
                         "12:37:04.325,2023-02-20 12:37:04.18,2023-02-20 "
                         "12:37:04.18\n")

    contents = buffer.getvalue()
    mock.get(file_url, content=contents.encode("utf-8"))
    lines = stream_file_stats()
    metrics = filelist_metrics(lines, default_min_report_size=0)
    # raise Exception(str(metrics))
    assert metrics['lst']['file_count'] == 3 * n_files
    assert metrics['lst']['data_size'] == 3 * n_files * file_size
    assert metrics['total']['file_count'] == 5 * n_files
    assert metrics['lst/1']['file_count'] == 2 * n_files
    assert metrics['lst/1']['data_size'] == 2 * n_files * file_size
    assert metrics['lst/1/2']['file_count'] == n_files
