import zipfile
import pathlib
import tempfile
import subprocess
import getpass
import os

unsignedPath = pathlib.Path.home() / "Desktop/zips"
signedPath = pathlib.Path.home() / "Desktop/signed_zips"

keystorePath = pathlib.Path("F:/SignProcess/JWS/codesigning.p12")
keyAlias = 'codesigning'

jarSignerPath = pathlib.Path('C:/Program Files/Java/jdk1.8.0_192/bin/jarsigner.exe')
netsignerPath = pathlib.Path('C:/Program Files (x86)/Windows Kits/10/Tools/bin/i386/signtool.exe')

tsa = "http://timestamp.globalsign.com/scripts/timestamp.dll"
proxyHost = "-J-Dhttp.proxyHost=proxy.bcssksz.local"
proxyPort = "-J-Dhttp.proxyPort=3128"


def assert_path_exists(path, errorMessage):
    if not path.exists():
        message = "ERROR : {errorMessage} [{path}]".format(errorMessage=errorMessage, path=str(path))
        raise FileNotFoundError(message)


def assert_external_toolresult(name, result, expected):
    if result.returncode is not 0:
        message = "    ERROR: [{name}] signing/verifying library. OUTPUT: {output}".format(name=name, output=str(result.stdout))
        raise Exception(message)
    else:
        if expected not in str(result.stdout):
            print("    WARN: [{name}] signing/verifying library. OUTPUT: {output}".format(name=name, output=str(result.stdout)))


def is_java_library(path):
    return path.suffix == '.jar'


def is_dotnet_library(path):
    return path.suffix == '.dll'


def sign_java_library(library, name):
    result = subprocess.run([str(jarSignerPath),
                             "-storetype", "pkcs12", "-strict",
                             "-keystore", str(keystorePath), "-storepass", keystorePassword,
                             "-keypass", keystorePassword,
                             "-tsa", tsa, proxyHost, proxyPort,
                             library.name, keyAlias], capture_output=True)
    assert_external_toolresult(name, result, "jar signed")
    result = subprocess.run([str(jarSignerPath), "-verify", "-storetype", "pkcs12", library.name], capture_output=True)
    assert_external_toolresult(name, result, "jar verified")
    return library


def sign_dotnet_library(library, name):
    result = subprocess.run([str(netsignerPath), "verify", "/pa", library.name], capture_output=True)
    if result.returncode is not 0:
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


assert_path_exists(unsignedPath, "Unsigned folder does not exist, you should be using")
assert_path_exists(signedPath, "Folder for signed libraries does not exist, please create")
assert_path_exists(keystorePath, "The keystore to be used for signing is not found in")
assert_path_exists(jarSignerPath, "JDK tool jarSigner can't be found, this file is part of any JDK installation")
assert_path_exists(netsignerPath, "Signtool can't be found, can be downloaded from Microsoft website")

if len(os.listdir(signedPath)) > 0:
    print("WARN: destination folder does not seem to be empty [{path}]".format(path=str(signedPath)))

cache = {}
globalCacheCounter = 0
keystorePassword = getpass.getpass("Keystore password : ")

for assembly in unsignedPath.glob('*.zip'):
    print("INFO: [{assembly}] processing assembly file".format(assembly=assembly.name))
    with zipfile.ZipFile(assembly, mode='r') as sourceZip, zipfile.ZipFile(signedPath / assembly.name, mode='x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as targetZip:
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
                        cache[zipEntry.CRC] = sign_java_library(library, zipEntryPath.name) if is_java_library(zipEntryPath) else sign_dotnet_library(library, zipEntryPath.name)
                        signedCounter += 1
                    with open(library.name, 'rb') as library:
                        targetZip.writestr(zipEntry.filename, library.read())
                else:
                    targetZip.writestr(zipEntry.filename, sourceZip.read(zipEntry))
        globalCacheCounter += cacheCounter
        print("INFO: [{assembly}] finished processing assembly file. Signed: {signed}, from cache: {cached}".format(assembly=assembly.name, signed=signedCounter, cached=cacheCounter))
print("INFO: All Done ! Signed {signed} libraries, {cached} from cache".format(signed=len(cache), cached=globalCacheCounter))
