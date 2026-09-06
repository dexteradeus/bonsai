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
