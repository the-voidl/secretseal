#!/usr/bin/env python3
import argparse
import base64
import os
import subprocess
import sys
import tempfile
from copy import deepcopy

import yaml

IS_TOUCHED = "touchedBySecretSeal"


def run(cmd, input_data=None):
    """Run a command and return its CompletedProcess instance."""
    try:
        result = subprocess.run(cmd, input=input_data, capture_output=True, text=True, check=True)
        return result
    except subprocess.CalledProcessError as e:
        printColorful(f"Error running command: {' '.join(cmd)}", 'red')
        printColorful(e.stderr, 'red')
        sys.exit(1)


def printColorful(text, color):
    """Print text in color."""
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "end": "\033[0m"
    }
    print(f"{colors[color]}{text}{colors['end']}")


def sealSecret(secretYaml, cert_file):
    """Use kubeseal to encrypt the secret."""
    # Write the secret YAML to a temporary file
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmpSecretFile:
        tmpSecretFile.write(secretYaml)
        tmpSecretPath = tmpSecretFile.name

    cmd = ["kubeseal", "--cert", cert_file, "-o", "yaml", "-f", tmpSecretPath]
    result = run(cmd)
    os.unlink(tmpSecretPath)  # remove temporary file
    return result.stdout


def decodeDataFields(secret):
    """Decode base64-encoded values in the data section of a yaml string"""
    data = secret.get("data")
    if data and isinstance(data, dict):
        decoded = {}
        for key, value in data.items():
            try:
                decodedValue = base64.b64decode(value).decode("utf-8")
            except Exception:
                # If decoding fails, leave value as-is.
                printColorful(f"Error decoding {key}", 'red')
                decodedValue = value
            decoded[key] = decodedValue
        secret["data"] = decoded
    return secret


def encodeDataFields(secrets):
    """Encode base64 values in the data section of a yaml string"""
    encodedSecrets = []
    for secret in secrets:
        data = secret.get("data")
        if data and isinstance(data, dict):
            encoded = {}
            for key, value in data.items():
                try:
                    encodedValue = base64.b64encode(value.encode("utf-8")).decode("utf-8")
                except Exception:
                    # If encoding fails, leave value as-is.
                    printColorful(f"Error encoding {key}", 'red')
                    encodedValue = value
                encoded[key] = encodedValue
            secret["data"] = encoded
        encodedSecrets.append(secret)
    dump = yaml.safe_dump_all(encodedSecrets)
    return yaml.safe_load_all(dump)


def editInteractively(secrets):
    """Edit the secrets interactively"""
    fileEndingsToIsolate = [".json", ".xml"]
    originalSecrets = deepcopy(secrets)
    secretsToModify = deepcopy(secrets)
    oneEdited = False
    editNoMore = False
    for secret in secretsToModify:
        for key, value in secret["data"].items():
            if not editNoMore:
                if oneEdited:
                    answer = input("Edit further keys isolated? (y/N) ")
                    if answer.lower() != "y":
                        editNoMore = True
                        break

                fileEnding = next((e for e in fileEndingsToIsolate if key.endswith(e)), None)
                if fileEnding:
                    printColorful(f"Found formatted data \033[1m{key} in secret {secret['metadata']['name']}", 'blue')
                    answer = input("Edit this key isolated? (y/N) ")
                    if answer.lower() == "y":
                        edited = editFile(value, fileEnding=fileEnding)
                        secret["data"][key] = edited
                        oneEdited = True


    editWholeFile = True
    if oneEdited:
        answer = input("Edit whole file? (y/N) ")
        editWholeFile = answer.lower() == "y"

    if editWholeFile:
        modifiedAsYaml = yaml.safe_dump_all(secretsToModify, sort_keys=False)
        secretsToModify = yaml.safe_load_all(editFile(modifiedAsYaml))

    return markModifiedSecrets(secretsToModify, originalSecrets)


def markModifiedSecrets(modifiedSecrets, originalSecrets):
    """Mark secrets as touched if they were edited"""
    newSecrets = []
    for secret in modifiedSecrets:
        name = secret["metadata"]["name"]
        namespace = secret["metadata"]["namespace"]
        oldSecret = next((s for s in originalSecrets if
                          s["metadata"]["name"] == name
                          and s["metadata"]["namespace"] == namespace), None)
        for key in secret.get("data", {}):
            if oldSecret["data"].get(key) != secret["data"].get(key):
                secret[IS_TOUCHED] = True
                break
        newSecrets.append(secret)

    dump = yaml.safe_dump_all(newSecrets, sort_keys=False)
    return dump



def editFile(initialContent, fileEnding=".yaml"):
    """Write content to a temporary file, open editor, then load the result."""
    editor = os.environ.get("EDITOR", "vi")
    with tempfile.NamedTemporaryFile(mode="w+", suffix=fileEnding, delete=False) as tmp:
        tmpPath = tmp.name
        tmp.write(initialContent)
        tmp.flush()
    # Open the editor
    subprocess.call([editor, tmpPath])
    # After editing, read the file back
    with open(tmpPath, "r") as f:
        editedContent = f.read()
    os.unlink(tmpPath)
    return editedContent


def getSecretsFromK8s(secrets):
    """Retrieve the secrets from k8s"""
    secretsFromK8s = []
    for secret in secrets:
        print(f"Getting secret {secret['metadata']['name']} from Kubernetes...")
        command = ["kubectl", "get", "secret", "-o", "yaml",
                   "-n", secret["metadata"]["namespace"],
                   secret["metadata"]["name"]]
        result = run(command)
        thisSecret = yaml.safe_load(result.stdout)
        secretsFromK8s.append(thisSecret)

    allSecrets = []
    for secret in secretsFromK8s:
        decoded = decodeDataFields(secret)
        allSecrets.append(
            {
                "apiVersion": decoded["apiVersion"],
                "data": decoded["data"],
                "kind": decoded["kind"],
                "metadata": {
                    "name": decoded["metadata"]["name"],
                    "namespace": decoded["metadata"]["namespace"]
                }
            })
    return allSecrets


def edit(args):
    """This is the routine for editing the sealed secret"""
    sealedSecretsFile = args.filename
    certFile = os.path.join(os.getcwd(), args.certfile)
    if not os.path.isfile(certFile):
        printColorful("Error: tls.crt file not found", 'red')
        sys.exit(1)
    if not os.path.isfile(sealedSecretsFile):
        printColorful(f"Error: File '{sealedSecretsFile}' not found.", 'red')
        sys.exit(1)

    secrets = []
    with open(sealedSecretsFile, "r") as f:
        try:
            fileStr = f.read()
            if not fileStr or fileStr.isspace():
                printColorful(f"File '{sealedSecretsFile}' is empty.", 'red')
                sys.exit(1)
            secrets = yaml.safe_load_all(fileStr)
        except Exception as e:
            printColorful(f"Error parsing YAML: {e}", 'red')
            sys.exit(1)

    originalSealedSecrets = []
    for secret in secrets:
        if secret.get("kind") == "SealedSecret":
            originalSealedSecrets.append(secret)

    if not any(originalSealedSecrets):
        printColorful("No secrets found in the YAML file.", 'red')
        sys.exit(1)

    allSecrets = getSecretsFromK8s(originalSealedSecrets)

    edited = editInteractively(allSecrets)

    try:
        editedSecret = yaml.safe_load_all(edited)
    except Exception as e:
        printColorful("Error parsing YAML after editing. Aborting.", 'red')
        printColorful(f"Error: {e}", 'red')
        sys.exit(1)

    with open(sealedSecretsFile, "w") as f:
        secretsToWrite = []
        for secret in encodeDataFields(editedSecret):
            name = secret["metadata"]["name"]
            namespace = secret["metadata"]["namespace"]
            touched = secret.get(IS_TOUCHED)
            originalSecret = next((s for s in originalSealedSecrets if
                                   s["metadata"]["name"] == name
                                   and s["metadata"]["namespace"] == namespace))
            if touched:
                modifiedSecret = sealSecret(yaml.safe_dump(secret), certFile)
                modifiedEncryptedData = yaml.safe_load(modifiedSecret)["spec"]["encryptedData"]
                originalSecret["spec"]["encryptedData"] = modifiedEncryptedData

            secretsToWrite.append(originalSecret)

        dump = yaml.safe_dump_all(secretsToWrite, sort_keys=False)
        f.write(dump)
        f.flush()

    print(f"Sealed secret updated in '{sealedSecretsFile}'.")


def main():
    try:
        parser = argparse.ArgumentParser(
            description=f"{sys.argv[0]}: Edit sealed secrets interactively"
        )
        subparsers = parser.add_subparsers(dest="command", required=True)

        editParser = subparsers.add_parser("edit", help="Edit a sealed secret")
        editParser.add_argument("filename", help="Path to the sealed secret YAML file")
        editParser.add_argument(
            "-c",
            "--cert",
            dest="certfile",
            default="../tls.crt",
            help="Path to the kubeseal certificate file (default: ../tls.crt).",
            required=False
        )

        args = parser.parse_args()

        if args.command == "edit":
            edit(args)
        else:
            parser.print_help()

    except KeyboardInterrupt:
        printColorful("Operation cancelled.", 'red')
        sys.exit(1)


if __name__ == "__main__":
    main()
