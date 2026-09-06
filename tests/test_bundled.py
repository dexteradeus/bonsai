import os
import pathlib
import subprocess
import sys

import pytest

import bonsai
from bonsai import _bundled

bundled_only = pytest.mark.skipif(
    not _bundled.is_bundled(),
    reason="only applies to wheels that bundle their own libraries",
)


@pytest.fixture
def probe(monkeypatch, tmp_path):
    """Drive find_ca_bundle() against a fake trust store, as if this were a wheel."""

    def configure(files=(), dirs=(), env=None):
        monkeypatch.setattr(_bundled, "is_bundled", lambda: True)
        monkeypatch.setattr(_bundled, "CA_BUNDLE_FILES", tuple(files))
        monkeypatch.setattr(_bundled, "CA_BUNDLE_DIRS", tuple(dirs))
        for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
            monkeypatch.delenv(name, raising=False)
        for name, value in (env or {}).items():
            monkeypatch.setenv(name, value)
        return _bundled.find_ca_bundle()

    return configure


def test_probe_skips_a_present_but_empty_directory(probe, tmp_path):
    """RHEL ships an empty /etc/ssl/certs, which would otherwise look like a valid answer.

    This is the failure the probe exists to avoid, and it is silent: TLS verification just
    fails later with no indication that an empty directory was chosen.
    """
    empty = tmp_path / "empty-certs"
    empty.mkdir()
    populated = tmp_path / "real-certs"
    populated.mkdir()
    (populated / "ca.pem").write_text("cert")

    assert probe(dirs=[str(empty), str(populated)]) == (None, str(populated))


def test_probe_returns_nothing_when_every_directory_is_empty(probe, tmp_path):
    empty = tmp_path / "empty-certs"
    empty.mkdir()
    assert probe(dirs=[str(empty)]) == (None, None)


def test_probe_skips_a_present_but_empty_bundle_file(probe, tmp_path):
    """An image that installs ca-certificates without running update-ca-certificates leaves
    an empty bundle at the first candidate path. Choosing it fails every verification while
    a populated bundle sits further down the list.
    """
    empty = tmp_path / "empty-bundle.crt"
    empty.touch()
    populated = tmp_path / "real-bundle.crt"
    populated.write_text("cert")

    assert probe(files=[str(empty), str(populated)]) == (str(populated), None)


def test_probe_skips_an_unreadable_directory(probe, tmp_path, monkeypatch):
    """Listing a directory can raise where stat does not, and the probe runs while a client
    is being constructed, so an unreadable trust store must not break LDAPClient().
    """
    unreadable = tmp_path / "unreadable-certs"
    unreadable.mkdir()
    populated = tmp_path / "real-certs"
    populated.mkdir()
    (populated / "ca.pem").write_text("cert")

    real_listdir = os.listdir

    def deny(path):
        if str(path) == str(unreadable):
            raise PermissionError(13, "Permission denied", str(path))
        return real_listdir(path)

    monkeypatch.setattr(os, "listdir", deny)

    assert probe(dirs=[str(unreadable), str(populated)]) == (None, str(populated))


def test_probe_prefers_a_bundle_file_over_a_directory(probe, tmp_path):
    bundle = tmp_path / "ca-bundle.crt"
    bundle.write_text("cert")
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "ca.pem").write_text("cert")

    assert probe(files=[str(bundle)], dirs=[str(certs)]) == (str(bundle), None)


def test_probe_takes_the_first_existing_candidate_in_order(probe, tmp_path):
    first = tmp_path / "first.crt"
    second = tmp_path / "second.crt"
    second.write_text("cert")
    third = tmp_path / "third.crt"
    third.write_text("cert")

    assert probe(files=[str(first), str(second), str(third)]) == (str(second), None)


def test_probe_finds_nothing_when_no_candidate_exists(probe, tmp_path):
    assert probe(files=[str(tmp_path / "absent.crt")], dirs=[str(tmp_path / "absent")]) == (
        None,
        None,
    )


@pytest.mark.parametrize("variable", ["SSL_CERT_FILE", "SSL_CERT_DIR"])
def test_probe_defers_to_the_openssl_environment_variables(probe, tmp_path, variable):
    """OpenSSL already honors these, and the caller may be pointing at a private store."""
    bundle = tmp_path / "ca-bundle.crt"
    bundle.write_text("cert")

    assert probe(files=[str(bundle)], env={variable: str(tmp_path / "elsewhere")}) == (
        None,
        None,
    )


def test_probe_is_inert_unless_the_build_is_bundled(monkeypatch, tmp_path):
    """A source build must keep whatever the system OpenSSL already does."""
    bundle = tmp_path / "ca-bundle.crt"
    bundle.write_text("cert")
    monkeypatch.setattr(_bundled, "is_bundled", lambda: False)
    monkeypatch.setattr(_bundled, "CA_BUNDLE_FILES", (str(bundle),))

    assert _bundled.find_ca_bundle() == (None, None)


def test_candidate_paths_are_absolute():
    """A relative path here would resolve against the working directory of the caller."""
    for path in _bundled.CA_BUNDLE_FILES + _bundled.CA_BUNDLE_DIRS:
        assert os.path.isabs(path), f"{path} is not absolute"


def test_client_defaults_to_the_probed_bundle(monkeypatch, tmp_path):
    """The probe is only useful if LDAPClient actually adopts its result."""
    bundle = tmp_path / "ca-bundle.crt"
    bundle.write_text("cert")
    monkeypatch.setattr(
        "bonsai.ldapclient.find_ca_bundle", lambda: (str(bundle), None)
    )
    assert bonsai.LDAPClient().ca_cert == str(bundle)


def test_explicit_ca_cert_overrides_the_probe(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "bonsai.ldapclient.find_ca_bundle", lambda: (str(tmp_path / "probed.crt"), None)
    )
    client = bonsai.LDAPClient()
    client.set_ca_cert("/explicit/ca.pem")
    assert client.ca_cert == "/explicit/ca.pem"


def test_source_build_probe_is_inert():
    """A source build must not change the default CA paths."""
    if _bundled.is_bundled():
        pytest.skip("this build bundles its own libraries")
    assert _bundled.find_ca_bundle() == (None, None)
    assert bonsai.LDAPClient().cert_policy == -1


@bundled_only
def test_bundled_licenses_are_shipped():
    """Redistributing these libraries in binary form requires shipping their licenses."""
    licenses = pathlib.Path(bonsai.__file__).parent / "licenses"
    assert licenses.is_dir(), f"{licenses} is missing from the wheel"
    shipped = {path.name for path in licenses.glob("*.txt")}
    for expected in ("openssl.txt", "cyrus-sasl.txt", "openldap.txt", "BUNDLED.txt"):
        assert expected in shipped, f"{expected} missing, have {sorted(shipped)}"
    for name in shipped:
        assert (licenses / name).stat().st_size > 0, f"{name} is empty"


@bundled_only
def test_bundled_inventory_lists_versions():
    """An auditor has to be able to match this wheel against a CVE without unpacking it."""
    inventory = pathlib.Path(bonsai.__file__).parent / "licenses" / "BUNDLED.txt"
    content = inventory.read_text()
    for library in ("openssl", "cyrus_sasl", "openldap"):
        assert library in content, f"{library} not listed in BUNDLED.txt"
    versions = [
        line for line in content.splitlines() if line and line[-1].isdigit() and "." in line
    ]
    assert len(versions) >= 3, f"expected three versioned entries, got {versions}"


@bundled_only
def test_extension_exports_only_its_init_symbol():
    """Generic globals in the extension would otherwise be able to collide with another one."""
    if not sys.platform.startswith("linux"):
        pytest.skip("nm and ELF symbol visibility are platform specific")
    out = subprocess.run(
        ["nm", "-D", "--defined-only", bonsai._bonsai.__file__],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        pytest.skip("nm is not available")
    exported = [line.split()[-1] for line in out.stdout.splitlines() if line.strip()]
    assert exported == ["PyInit__bonsai"], f"unexpected exports: {exported}"


@bundled_only
def test_no_system_ldap_or_sasl_is_used():
    """The wheel has to resolve its own libraries, not whatever the host happens to have."""
    if not sys.platform.startswith("linux"):
        pytest.skip("ldd is Linux specific")
    out = subprocess.run(
        ["ldd", bonsai._bonsai.__file__], capture_output=True, text=True
    )
    if out.returncode != 0:
        pytest.skip("ldd is not available")
    for line in out.stdout.splitlines():
        if any(name in line for name in ("libldap", "liblber", "libsasl")):
            assert "bonsai.libs" in line, f"resolved outside the wheel: {line.strip()}"


@bundled_only
@pytest.mark.parametrize("order", [("ssl", "bonsai"), ("bonsai", "ssl")])
def test_stdlib_ssl_is_unaffected(order):
    """The bundled OpenSSL must not displace the one the stdlib ssl module uses.

    Both import orders are checked, because this is a dynamic loader problem and the
    answer can differ depending on which OpenSSL is mapped first.
    """
    code = (
        f"import {order[0]}; import {order[1]}; import ssl, json;"
        " print(json.dumps({'v': ssl.OPENSSL_VERSION,"
        " 'ctx': bool(ssl.create_default_context())}))"
    )
    baseline = subprocess.run(
        [sys.executable, "-c", "import ssl; print(ssl.OPENSSL_VERSION)"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr
    assert baseline in out.stdout, f"stdlib ssl changed: {baseline!r} vs {out.stdout!r}"
    assert '"ctx": true' in out.stdout.replace("'", '"').lower()
