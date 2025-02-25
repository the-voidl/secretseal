# secretseal

Annoyed of handling sealed secrets in your kubernetes cluster? This tool is for you!

## What this script does

1. Reads a sealed secret resource as input
2. Obtains the decrypted secrets from your cluster
3. Lets you interactively edit the decrypted secrets in your favourite editor
    - The secret values get decoded and displayed human-readable
    - If json data is detected in the secret, you can edit it seperately
5. Encrypts the secrets back and updates the sealed secret resource

## Pre-requisites

- You have direct access to the kubernetes cluster
- You use a git-first workflow
- You use bitnamis sealed secrets

## Requirements

- kubectl
- kubeseal

## Basic usage

```bash
./secretseal.sh <sealed-secret-file> -c <path-to-sealed-secrets-certificate>
```
1. Edit the secrets
2. Save and exit
3. Review the changes
4. Git push

## Warnings

- This script will overwrite the original sealed secret file
- Edited secrets won't be applied to the cluster automatically
- You cannot edit a secret iteratively, since the actual secrets are read from the cluster
- This will not be actively maintained

