#!/usr/bin/env python3
import os
import jwt
import time
import requests
import json
from pathlib import Path

# Load env vars
env_file = Path(".env")
env_vars = {}
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                env_vars[key] = value.strip('"')

app_id = env_vars.get("GITHUB_APP_ID")
installation_id = env_vars.get("GITHUB_APP_INSTALLATION_ID")
private_key = env_vars.get("GITHUB_APP_PRIVATE_KEY", "").replace("\\n", "\n")

if not all([app_id, installation_id, private_key]):
    print("Missing GitHub App credentials")
    exit(1)

# Generate JWT
now = int(time.time())
payload = {
    "iat": now - 60,
    "exp": now + 600,
    "iss": app_id
}

jwt_token = jwt.encode(payload, private_key, algorithm="RS256")

# Get installation access token
headers = {
    "Authorization": f"Bearer {jwt_token}",
    "Accept": "application/vnd.github.v3+json"
}

response = requests.post(
    f"https://api.github.com/app/installations/{installation_id}/access_tokens",
    headers=headers
)

if response.status_code != 201:
    print(f"Failed to get installation token: {response.status_code}")
    print(response.text)
    exit(1)

access_token = response.json()["token"]
print("✅ Got installation access token")

# Create repository
repo_name = "pactum"
owner = "danvoulez"

headers = {
    "Authorization": f"token {access_token}",
    "Accept": "application/vnd.github.v3+json"
}

repo_data = {
    "name": repo_name,
    "description": "Pactum RiskPact V0.2 - Deterministic protocol for canonical JSON, hashing, and Ed25519 signatures",
    "private": False,
    "auto_init": False
}

response = requests.post(
    f"https://api.github.com/repos/{owner}/{repo_name}",
    headers=headers,
    json=repo_data
)

if response.status_code == 201:
    print(f"✅ Repository {owner}/{repo_name} created")
elif response.status_code == 422:
    print(f"⚠️  Repository {owner}/{repo_name} already exists")
else:
    print(f"Failed to create repository: {response.status_code}")
    print(response.text)
    exit(1)

print(f"\nRepository URL: https://github.com/{owner}/{repo_name}")
print(f"\nAccess token (valid 1 hour): {access_token[:20]}...")

