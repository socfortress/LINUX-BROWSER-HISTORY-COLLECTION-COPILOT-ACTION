## Browser-history-and-acrtifacts-collection.sh

This script collects browser artifacts such as history, bookmarks, downloads, and cookies from Chrome/Chromium, Edge, and Firefox profiles for all users, providing a JSON-formatted output for integration with your SIEM.

### Overview

The `Browser-history-and-acrtifacts-collection.sh` script scans user browser profiles for Chrome/Chromium, Edge, and Firefox, extracting relevant artifacts using SQLite queries and direct file reads. Output is formatted as JSON for active response workflows.

### Script Details

#### Core Features

1. **Multi-Browser Support**: Collects artifacts from Chrome/Chromium, Edge, and Firefox.
2. **Artifact Extraction**: Gathers history, bookmarks, downloads, and cookies.
3. **User Coverage**: Scans all user home directories and root.
4. **JSON Output**: Generates a structured JSON report for integration with security tools.
5. **Logging Framework**: Provides detailed logs for script execution.
6. **Log Rotation**: Implements automatic log rotation to manage log file size.
7. **SQLite Handling**: Automatically installs `sqlite3` if missing (where possible).

### How the Script Works

#### Command Line Execution
```bash
./Browser-history-and-acrtifacts-collection.sh
```

#### Parameters

| Parameter | Type | Default Value | Description |
|-----------|------|---------------|-------------|
| `ARLog`   | string | `/var/ossec/active-response/active-responses.log` | Path for active response JSON output |
| `LogPath` | string | `/tmp/Browser-history-and-acrtifacts-collection.sh-script.log` | Path for detailed execution logs |
| `LogMaxKB` | int | 100 | Maximum log file size in KB before rotation |
| `LogKeep` | int | 5 | Number of rotated log files to retain |

### Script Execution Flow

#### 1. Initialization Phase
- Clears the active response log file
- Rotates the detailed log file if it exceeds the size limit
- Logs the start of the script execution
- Checks for and installs `sqlite3` if missing

#### 2. Artifact Collection
- For each user, scans browser profile directories
- Extracts history, bookmarks, downloads, and cookies using SQLite queries and file reads

#### 3. JSON Output Generation
- Formats browser artifacts into a JSON object
- Writes the JSON result to the active response log

### JSON Output Format

#### Example Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Browser-history-and-acrtifacts-collection.sh",
  "data": {
    "chrome_chromium": {
      "user1-google-chrome": {
        "history": [ ... ],
        "bookmarks": "...",
        "downloads": [ ... ],
        "cookies": [ ... ]
      }
    },
    "edge": {
      "user1-edge": {
        "history": [ ... ],
        "bookmarks": "...",
        "downloads": [ ... ],
        "cookies": [ ... ]
      }
    },
    "firefox": {
      "user1-firefox": {
        "history": [ ... ],
        "downloads": [ ... ],
        "cookies": [ ... ]
      }
    }
  },
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to access browser profile files
- Validate the JSON output for compatibility with your security tools
- Test the script in isolated environments

#### Security Considerations
- Ensure minimal required privileges
- Protect the output log files and browser data

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure read access to browser profile directories
2. **Missing Data**: Some profiles may not exist or may be locked
3. **Log File Issues**: Check write permissions
4. **Missing sqlite3**: Ensure `sqlite3` is installed or installable

#### Debugging
Enable verbose logging:
```bash
VERBOSE=1 ./Browser-history-and-acrtifacts-collection.sh
```

### Contributing

When modifying this script:
1. Maintain the browser artifact collection and JSON output structure
2. Follow Shell scripting best practices
3. Document any additional functionality
4. Test thoroughly in isolated environments
