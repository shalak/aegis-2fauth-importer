# Aegis 2FAuth Importer

## Overview
The Aegis 2FAuth Importer is a Python-based tool that facilitates the migration of encrypted 
Aegis 2FA backups into a 2FAuth instance. It supports both REST API mode (server) and command-line 
interface (CLI) mode for flexible integration.

## Features
- Decrypts Aegis encrypted backup files
- Imports 2FA accounts into 2FAuth
- Supports REST API server mode and CLI mode
- Provides detailed import reports

## Prerequisites
Ensure you have the following installed:
- Docker
- Docker Compose

## Installation
1. Clone this repository:
```bash
git clone https://github.com/shalak/aegis-2fauth-importer.git
cd aegis-2fauth-importer
```

2. Build the Docker image:
```bash
docker-compose build
```

## Configuration (CLI Mode Only)
Create an `aegis.env` file with the following environment variables:
```ini
AEGIS_PASS=your_aegis_password
URL_2FAUTH=https://your-2fauth-instance.com
BEARER_2FAUTH=your_personal_access_token
```

## Usage

### 1. Server Mode (REST API)
To run the application as a REST API server:
```bash
docker-compose up aegis-2fauth-importer-server
```

Example API call:
```bash
curl -X POST http://localhost:5000/upload \
    -F "file=@path/to/encrypted/backup.json" \
    -F "url=$URL_2FAUTH" \
    -F "token=$BEARER_2FAUTH" \
    -F "password=$AEGIS_PASS" \
    -H "Content-Type: multipart/form-data"
```

### 2. CLI Mode
To run in CLI mode and import a backup file:
1. Place the backup file in `./vaults/aegis-backup.json`.
2. Execute the following command:
```bash
docker-compose run --rm aegis-2fauth-importer
```

## Environment Variables
| Variable         | Description                              |
|------------------|------------------------------------------|
| `AEGIS_PASS`     | Password for the encrypted Aegis backup  |
| `URL_2FAUTH`     | URL of the 2FAuth instance               |
| `BEARER_2FAUTH`  | API token for 2FAuth authentication      |

Environment variables are required only for CLI mode. In REST API mode, they are optional; if set, they
won't need to be provided in API requests.


## Output
The tool generates a report with the following sections:
- `imported`: Successfully imported accounts
- `skipped`: Accounts already existing in 2FAuth
- `invalid`: Invalid entries from the backup
- `errors`: Any errors encountered during the process

## Example Output
```json
{
  "imported": ["Google - user@example.com"],
  "skipped": ["Facebook - user@example.com (already exists)"],
  "invalid": [],
  "errors": []
}
```

## Troubleshooting
1. Ensure environment variables are correctly set (CLI mode only).
2. Check Docker logs for errors:
```bash
docker-compose logs
```

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.


## Acknowledgments
- [Aegis Authenticator](https://getaegis.app/)
- [2FAuth](https://2fauth.app/)
