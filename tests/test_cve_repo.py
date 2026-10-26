def ids(repo, product, version):
    return {r.cve_id for r in repo.find(product, version)}


def test_vsftpd_backdoor(repo):
    assert ids(repo, "vsftpd", "2.3.4") == {"CVE-2011-2523"}
    assert not ids(repo, "vsftpd", "3.0.5")


def test_openssh_version_ranges(repo):
    assert {"CVE-2016-10009", "CVE-2018-15473"} <= ids(repo, "OpenSSH", "7.2p2")
    assert ids(repo, "OpenSSH", "7.4p1") == {"CVE-2018-15473"}  # 7.4p1 fixed 10009, still < 7.8
    assert not ids(repo, "OpenSSH", "9.6p1")


def test_samba_multi_range(repo):
    assert "CVE-2017-7494" in ids(repo, "Samba smbd", "4.5.9")
    assert "CVE-2017-7494" not in ids(repo, "Samba smbd", "4.5.10")


def test_apache_and_unknown(repo):
    assert ids(repo, "Apache httpd", "2.4.49") == {"CVE-2021-41773", "CVE-2021-42013"}
    assert ids(repo, "Apache httpd", "2.4.50") == {"CVE-2021-42013"}
    assert not ids(repo, "Totally Unknown", "1.0")
