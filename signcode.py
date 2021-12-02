import zipfile
import pathlib
import tempfile
import subprocess
import getpass
import os
import argparse

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


def assert_path_exists(path, errorMessage):
    if not path.exists():
        message = "ERROR : {errorMessage} [{path}]".format(errorMessage=errorMessage, path=str(path))
        raise FileNotFoundError(message)


def assert_external_toolresult(name, result, expected):
    if result.returncode != 0:
        message = "    ERROR: [{name}] signing/verifying library. OUTPUT: {output}".format(name=name, output=str(result.stdout))
        raise Exception(message)
    else:
        if expected not in str(result.stdout):
            print("    WARN: [{name}] signing/verifying library. OUTPUT: {output}".format(name=name, output=str(result.stdout)))


def is_java_library(path):
    return path.suffix == '.jar'


def is_dotnet_library(path):
    return path.suffix == '.dll'


def sign_java_library(library, name, jarSignerPath, keystorePath, keyAlias, keystorePassword, tsa):
    result = subprocess.run([str(jarSignerPath),
                             "-storetype", "pkcs12", "-strict",
                             "-keystore", str(keystorePath), "-storepass", keystorePassword,
                             "-keypass", keystorePassword,
                             "-tsa", tsa, PROXY_HOST, PROXY_PORT,
                             library.name, keyAlias], capture_output=True)
    assert_external_toolresult(name, result, "jar signed")
    result = subprocess.run([str(jarSignerPath), "-verify", "-storetype", "pkcs12", library.name], capture_output=True)
    assert_external_toolresult(name, result, "jar verified")
    return library


def sign_dotnet_library(library, name, netsignerPath, keystorePath, keystorePassword, tsa):
    result = subprocess.run([str(netsignerPath), "verify", "/pa", library.name], capture_output=True)
    if result.returncode != 0:
        result = subprocess.run(
            [str(netsignerPath), "sign", "/fd", "sha256", "/f", str(keystorePath), "/p", keystorePassword,
             library.name], capture_output=True)
        assert_external_toolresult(name, result, "")
        result = subprocess.run([str(netsignerPath), "timestamp", "/t", tsa, library.name], capture_output=True)
        assert_external_toolresult(name, result, "")
        result = subprocess.run([str(netsignerPath), "verify", "/pa", library.name], capture_output=True)
        assert_external_toolresult(name, result, "")
    else:
        print("    WARN: [{name}] Library appears to be already signed, it will not be signed again".format(name=name))
    return library


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="signcode", description='signs java libraries for release for Java and .NET')
    parser.add_argument('--src', help='folder containing assemblies to be signed', type=pathlib.Path)
    parser.add_argument('--dst', help='folder to save signed assemblies', type=pathlib.Path)
    parser.add_argument('--keystore', help='keystore location .p12 file', type=pathlib.Path)
    parser.add_argument('--alias', help='key alias in the keystore', type=str, default="codesigning")
    parser.add_argument('--jarsigner', help='java signing tool location: jarsigner.exe', type=pathlib.Path)
    parser.add_argument('--signtool', help='.NET signing tool location: signtool.exe', type=pathlib.Path)
    parser.add_argument('--tsa', help='public free timestamping server', type=str)
    parser.set_defaults(**DEFAULT_VALUES)
    args = parser.parse_args()

    assert_path_exists(args.src, "Unsigned folder does not exist, you should be using")
    assert_path_exists(args.dst, "Folder for signed libraries does not exist, please create")
    assert_path_exists(args.keystore, "The keystore to be used for signing is not found in")
    assert_path_exists(args.jarsigner, "JDK tool jarSigner can't be found, this file is part of any JDK installation")
    assert_path_exists(args.signtool, "Signtool can't be found, can be downloaded from Microsoft website")


    if len(os.listdir(args.src)) > 0:
        print("WARN: destination folder does not seem to be empty [{path}]".format(path=str(args.dst)))

    cache = {}
    globalCacheCounter = 0
    keystorePassword = getpass.getpass("Keystore password : ")

    for assembly in args.src.glob('*.zip'):
        print("INFO: [{assembly}] processing assembly file".format(assembly=assembly.name))
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
                            print("  INFO: [{name}] signing library".format(name=zipEntryPath.name))
                            cache[zipEntry.CRC] = sign_java_library(library, zipEntryPath.name, args.jarsigner, args.keystore, args.alias, keystorePassword, args.tsa) if is_java_library(zipEntryPath) else sign_dotnet_library(library, zipEntryPath.name, args.signtool, args.keystore, args.alias, keystorePassword, args.tsa)
                            signedCounter += 1
                        with open(library.name, 'rb') as library:
                            targetZip.writestr(zipEntry.filename, library.read())
                    else:
                        targetZip.writestr(zipEntry.filename, sourceZip.read(zipEntry))
            globalCacheCounter += cacheCounter
            print("INFO: [{assembly}] finished processing assembly file. Signed: {signed}, from cache: {cached}".format(
                assembly=assembly.name, signed=signedCounter, cached=cacheCounter))
    print("INFO: All Done ! Signed {signed} libraries, {cached} from cache".format(signed=len(cache), cached=globalCacheCounter))
