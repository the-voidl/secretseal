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

- You have direct access to the kubernetes cluster through kubectl
- You use a git-first workflow
- You use [bitnami's sealed secrets](https://github.com/bitnami-labs/sealed-secrets)

## Requirements

- kubectl
- [kubeseal](https://github.com/bitnami-labs/sealed-secrets/blob/main/docs/developer/kubeseal.md)
- python3

## Basic usage

```bash
./secretseal.py edit <sealed-secret-file> -c <path-to-sealed-secrets-certificate>
```
1. Edit the secrets
2. Save and exit
3. Review the changes
4. Git push

## Example
Our git repository is structured as follows:
```
.
└── k8s
    ├── cluster1
    │   ├── namespace1
    │   │   ├── deployment.yaml
    │   │   └── application-secrets.yaml
    │   ├── namespace2
    │   │   ├── deploymentA.yaml
    │   │   ├── deploymentB.yaml
    │   │   ├── mail-secrets.yaml
    │   │   └── db-secrets.yaml
    │   └── crt.tls             <-- this is the sealed secret certificate (gitignored)
    └── cluster2
        └── crt.tls
    
```
My workflow so far was:
1. I get the certificate from the cluster by running `kubeseal --fetch-cert --controller-namespace <namespace> > crt.tls`
2. I obtain the decrypted secret(s) from the cluster
3. I edit the secret
4. If some keys are json, I copy the json data to a temporary file to have highlighting and linting
5. I copy all values back to one file
6. I create a secret with `kubectl create secret generic mail-secrets --from-file=secret.json --dry-run=client -o yaml > application-secrets-plain.yaml`
7. I encrypt the secret with `kubeseal --cert crt.tls < application-secrets-plain.yaml > application-secrets.yaml`

Now I can do all of this with two commands when in the `k8s/cluster1/namespace1` directory:
```bash
kubeseal --fetch-cert --controller-namespace <namespace> > ../crt.tls
./secretseal.py edit application-secrets.yaml
```

## Warnings

- This script will overwrite the original sealed secret file
- Edited secrets won't be applied to the cluster automatically -> git-first workflow
- You cannot edit a secret interatively, since the actual secrets are read from the cluster
- This will not be actively maintained

