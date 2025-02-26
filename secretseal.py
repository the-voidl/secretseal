#!/usr/bin/env python3
import argparse
import base64
import os
import subprocess
import sys
import tempfile

import yaml


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


def sealSecret(secret_yaml, cert_file):
    """Use kubeseal to encrypt the secret."""
    # Write the secret YAML to a temporary file
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_secret:
        tmp_secret.write(secret_yaml)
        tmp_secret_path = tmp_secret.name

    cmd = ["kubeseal", "--cert", cert_file, "-o", "yaml", "-f", tmp_secret_path]
    result = run(cmd)
    os.unlink(tmp_secret_path)  # remove temporary file
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
    """Edit the secrets interactively."""
    # if there is one secret containing json data, ask to only edit that key
    result = []
    oneEdited = False
    editNoMore = False
    for secret in secrets:
        for key, value in secret["data"].items():
            if key.endswith(".json") and not editNoMore:
                if oneEdited:
                    answer = input("Edit further keys isolated? (Y/n) ")
                    if answer.lower() == "n":
                        editNoMore = True
                        break

                print(f"Found JSON data \033[1m{key}\033[0m in secret {secret['metadata']['name']}")
                answer = input("Edit this key isolated? (y/N) ")
                if answer.lower() == "y":
                    edited = editFile(value, fileEnding=".json")
                    secret["data"][key] = edited
                    result.append(secret)
                    oneEdited = True
                    break
        else:
            result.append(secret)

    yamlString = yaml.safe_dump_all(result, sort_keys=False)

    editWholeFile = True
    if oneEdited:
        answer = input("Edit whole file? (y/N) ")
        editWholeFile = answer.lower() == "y"

    if editWholeFile:
        return editFile(yamlString, fileEnding=".yaml")

    return yamlString


def editFile(initialContent, fileEnding=".yaml"):
    """Write content to a temporary file, open editor, then load the result."""
    editor = os.environ.get("EDITOR", "vi")
    with tempfile.NamedTemporaryFile(mode="w+", suffix=fileEnding, delete=False) as tmp:
        tmpPath = tmp.name
        tmp.write(initialContent)
        tmp.flush()
    # Open the editor
    subprocess.call([editor, tmpPath])
    # After editing, read the file back.
    with open(tmpPath, "r") as f:
        edited_content = f.read()
    os.unlink(tmpPath)
    return edited_content


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
            file_str = f.read()
            if not file_str or file_str.isspace():
                printColorful(f"File '{sealedSecretsFile}' is empty.", 'red')
                sys.exit(1)
            secrets = yaml.safe_load_all(file_str)
        except Exception as e:
            printColorful(f"Error parsing YAML: {e}", 'red')
            sys.exit(1)

    secretsArray = []
    for secret in secrets:
        if secret.get("kind") == "SealedSecret":
            secretsArray.append(secret)

    if not any(secretsArray):
        printColorful("No secrets found in the YAML file.", 'red')
        sys.exit(1)

    allSecrets = getSecretsFromK8s(secretsArray)

    edited = editInteractively(allSecrets)

    try:
        editedSecret = yaml.safe_load_all(edited)
    except Exception as e:
        printColorful("Error parsing YAML after editing. Aborting.", 'red')
        printColorful(f"Error: {e}", 'red')
        sys.exit(1)

    # Dump the updated secret YAML
    encoded = encodeDataFields(editedSecret)
    updatedYaml = yaml.safe_dump_all(encoded, sort_keys=False)

    # Encrypt the updated secret using kubeseal
    sealed = sealSecret(updatedYaml, certFile)

    # Overwrite the original file with the sealed secret
    with open(sealedSecretsFile, "w") as f:
        f.write(sealed)

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
