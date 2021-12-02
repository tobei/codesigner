import zipfile
import pathlib
import tempfile
import subprocess
import getpass
import os
import argparse
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone

DEFAULT_VALUES = {
    "src": pathlib.Path.home() / "Desktop/zips",
    "dst": pathlib.Path.home() / "Desktop/signed_zips",
    "keystore": pathlib.Path("F:/SignProcess/JWS/codesigning.p12"),
    "alias": "codesigning",
    "jarsigner": pathlib.Path('C:/Program Files/Java/jdk1.8.0_192/bin/jarsigner.exe'),
    "signtool": pathlib.Path('C:/Program Files (x86)/Windows Kits/10/Tools/bin/i386/signtool.exe'),
    "tsa": "http://timestamp.globalsign.com/scripts/timestamp.dll"
}

PROXY_HOST = "-J-Dhttp.proxyHost=proxy.bcssksz.local"
PROXY_PORT = "-J-Dhttp.proxyPort=3128"


def assert_path_exists(path, error_message):
    if not path.exists():
        print("ERROR", f"{error_message} [{str(path)}]")
        return False
    return True


def assert_external_toolresult(name, result, expected):
    if result.returncode != 0:
        message = f"    ERROR: [{name}] signing/verifying library. OUTPUT: {str(result.stdout)}"
        raise AssertionError(message)
    else:
        if expected not in str(result.stdout):
            print("    ", "WARN", f"[{name}] signing/verifying library. OUTPUT: {str(result.stdout)}")


def is_java_library(path):
    return path.suffix == '.jar'


def is_dotnet_library(path):
    return path.suffix == '.dll'


def sign_java_library(lib, name, jarsigner_path, keystore_path, key_alias, keystore_password, timestamp_url):
    result = subprocess.run([str(jarsigner_path),
                             "-storetype", "pkcs12", "-strict",
                             "-keystore", str(keystore_path), "-storepass", keystore_password,
                             "-keypass", keystore_password,
                             "-tsa", timestamp_url, PROXY_HOST, PROXY_PORT,
                             lib.name, key_alias], capture_output=True)
    assert_external_toolresult(name, result, "jar signed")
    result = subprocess.run([str(jarsigner_path), "-verify", "-storetype", "pkcs12", lib.name], capture_output=True)
    assert_external_toolresult(name, result, "jar verified")
    return lib


def sign_dotnet_library(lib, name, signtool_path, keystore_path, key_alias, timestamp_url):
    result = subprocess.run([str(signtool_path), "verify", "/pa", lib.name], capture_output=True)
    if result.returncode != 0:
        result = subprocess.run(
            [str(signtool_path), "sign", "/fd", "sha256", "/f", str(keystore_path), "/p", key_alias,
             lib.name], capture_output=True)
        assert_external_toolresult(name, result, "")
        result = subprocess.run([str(signtool_path), "timestamp", "/t", timestamp_url, lib.name], capture_output=True)
        assert_external_toolresult(name, result, "")
        result = subprocess.run([str(signtool_path), "verify", "/pa", lib.name], capture_output=True)
        assert_external_toolresult(name, result, "")
    else:
        print("    ", "WARN", f"[{name}] Library appears to be already signed, it will not be signed again")
    return lib


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="signcode", description='signs java libraries for release for Java and .NET')
    parser.add_argument('--src', help='folder containing assemblies to be signed', type=pathlib.Path)
    parser.add_argument('--dst', help='folder to save signed assemblies', type=pathlib.Path)
    parser.add_argument('--keystore', help='keystore location .p12 file', type=pathlib.Path)
    parser.add_argument('--alias', help='key alias in the keystore', type=str, default="codesigning")
    parser.add_argument('--jarsigner', help='java signing tool location: jarsigner.exe', type=pathlib.Path)
    parser.add_argument('--signtool', help='.NET signing tool location: signtool.exe', type=pathlib.Path)
    parser.add_argument('--tsa', help='public free timestamping server url', type=str)
    parser.set_defaults(**DEFAULT_VALUES)
    args = parser.parse_args()

    print("Signing configuration:")
    for key, value in vars(args).items():
        print(" ", key.ljust(12), "=", value)

    paths = [
        (args.src, "Unsigned folder does not exist, create it or change it"),
        (args.dst, "Folder for signed libraries does not exist, create it or change it"),
        (args.keystore, "No keystore found at the given location"),
        #(args.jarsigner, "JDK tool jarSigner can't be found, this file is part of any JDK installation"),
        #(args.signtool, "Signtool can't be found, can be downloaded from Microsoft website")
    ]

    if not all([assert_path_exists(path, error_message) for (path, error_message) in paths]):
        raise AssertionError("ERROR: Some necessary locations are missing")


    if len(os.listdir(args.src)) > 0:
        print("WARN", f"destination folder does not seem to be empty [{str(args.dst)}]")

    print("INFO", f"Keystore access and content will now be evaluated")
    keystorePassword = getpass.getpass("Keystore password : ")
    with open(args.keystore, 'rb') as p12:
        keystore = pkcs12.load_pkcs12(p12.read(), keystorePassword.encode())
        assert keystore.key, "No private key in this P12, can't sign"
        assert keystore.cert, "Can't find certificate in this P12"
        assert keystore.cert.friendly_name == args.alias.encode(), "Incorrect alias for the certificate"
        assert keystore.cert.certificate.fingerprint(hashes.SHA256()).hex() == "3fb5cedac685b02604f5a79211c6eff4d235bd62061a0da80d4cb0a16dce2828", "Unknown certificate, if new one please update fingerprint"
        expiresIn = keystore.cert.certificate.not_valid_after.astimezone(timezone.utc) - datetime.now(timezone.utc)

        if expiresIn.days < 90:
            print("WARN", f"Signing certificate expires in {expiresIn.days} days")
        else:
            print("INFO", f"Signing certificate expires in {expiresIn.days} days")
    print("INFO", f"Keystore sanity check successful")

    cache = {}
    globalCacheCounter = 0

    for assembly in args.src.glob('*.zip'):
        print("INFO", f"[{assembly.name}] processing assembly file")
        with zipfile.ZipFile(assembly, mode='r') as sourceZip, zipfile.ZipFile(args.dst / assembly.name, mode='x', mpression=zipfile.ZIP_DEFLATED, compresslevel=9) as targetZip:
            cacheCounter = 0
            signedCounter = 0
            for zipEntry in sourceZip.infolist():
                if not zipEntry.is_dir():
                    zipEntryPath = pathlib.PurePath(zipEntry.filename)
                    if is_java_library(zipEntryPath) or is_dotnet_library(zipEntryPath):
                        if zipEntry.CRC in cache:
                            library = cache[zipEntry.CRC]
                            cacheCounter += 1
                        else:
                            library = tempfile.NamedTemporaryFile(delete=False)
                            library.write(sourceZip.read(zipEntry))
                            library.close()
                            print("  ", "INFO", f"[{zipEntryPath.name}] signing library")
                            cache[zipEntry.CRC] = sign_java_library(library, zipEntryPath.name, args.jarsigner, args.keystore, args.alias, keystorePassword, args.tsa) if is_java_library(zipEntryPath) else sign_dotnet_library(library, zipEntryPath.name, args.signtool, args.keystore, args.alias, keystorePassword, args.tsa)
                            signedCounter += 1
                        with open(library.name, 'rb') as library:
                            targetZip.writestr(zipEntry.filename, library.read())
                    else:
                        targetZip.writestr(zipEntry.filename, sourceZip.read(zipEntry))
            globalCacheCounter += cacheCounter
            print("INFO", f"[{assembly.name}] finished processing assembly file. Signed: {signedCounter}, from cache: {cacheCounter}")
    print("INFO", f"All Done ! Signed {len(cache)} libraries, {globalCacheCounter} from cache")
