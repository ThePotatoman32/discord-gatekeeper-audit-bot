# Discord Gatekeeper Cleaner

Work in progress Discord Bot that will eventually act as a Gatekeeper and an auditor of those who idle in gate channels. Will also act as an unverifier for users that were previously verified but are no longer meeting criteria. VERY BETA. USE AT YOUR OWN RISK.

## Key Features

*   **🎯 Automated User Tracking**: Identifies and monitors users assigned a specific "Unverified" role.
*   **🔍 Status Management**: Automatically categorizes users in its database as `Unverified`, `Verified` (gained other roles), or `Invalid` (no roles besides @everyone after losing Unverified status).
*   **⚙️ Periodic Scans**: Regularly scans all server members to update user statuses, add new unverified members, and identify those who have left.
*   **🔔 Verification Reminders (`/poke`)**: Sends configurable reminders via Direct Message (DM) or channel pings to prompt users to complete verification. Tracks reminder counts.
*   **📊 User Statistics**: Stores server join dates, account creation dates, reminder counts, and scan history for tracked users.
*   **💾 Robust Database Management**: Utilizes SQLite for efficient data storage with WAL mode enabled for better concurrency. Includes schema versioning.
*   **🛡️ Automated Backups**: Performs regular scheduled backups and creates safety backups before critical operations (scans, restores, user removals). Backup reasons are included in filenames.
*   **🛠️ Admin Command Suite (`/gatekeeper`)**: Intuitive slash commands for server staff to manually scan, list users by status, and send reminders.
*   **🧑‍💻 Developer Tools (`/dev`)**: Advanced commands for managing the bot itself, including configuration updates (runtime and persistent), database health checks, backups, restores, and safe reloads.
*   **📝 Detailed Logging**: Comprehensive logging to both files (`logs/gatekeeper.log`) and dedicated Discord channels for transparency and troubleshooting (general summaries vs. detailed developer logs).
*   **📨 DM Forwarding**: Captures DM responses sent to the bot (e.g., replies to `/poke dm`) and forwards them to a designated channel for review, including the sender's tracked status.
*   **👋 Leave Logging**: Logs detailed information about tracked users when they leave the server to a designated channel.
*   **✅ Startup Sequence & Audit**: Performs database health checks and data consistency audits on startup, reporting status to designated channels. Initializes the database schema on first run. Runs an initial scan shortly after startup.

## Configuration (`config.yaml`)

This file is essential for controlling the bot's behavior.

```yaml
# --- Core Settings ---
# Name of the environment variable holding the Discord Bot Token (defined in your .env file)
discord_token_env: "DISCORD_BOT_TOKEN" # Default: DISCORD_BOT_TOKEN
# Your Discord Server's unique ID.
guild_id: 123456789012345678 # MUST BE SET

# --- Role IDs ---
# Role IDs from your server.
roles:
  # Role required to use /gatekeeper commands (e.g., Moderators). Set to 0 or null to allow only developers.
  general_command_role_id: 123456789012345678
  # Role required to use /dev commands (e.g., Bot Admins). Set to 0 or null to disable dev commands.
  developer_role_id: 123456789012345678
  # The ID of the role assigned to unverified users. The bot tracks users with this role.
  unverified_role_id: 1351008836655517736 # MUST BE SET - Example from logs

# --- Channel IDs ---
# Channel IDs from your server.
channels:
  # Channel for general command summaries, startup status, and forwarded DMs.
  general_responses_channel_id: 1356609960317948084 # Example from logs
  # Channel for detailed startup logs, scan logs, errors, dev command outputs.
  dev_logs_channel_id: 1354679113389965426 # Example from logs
  # The "gate" or "verify-here" channel where /poke gate pings occur.
  gate_channel_id: 1351008836655517736 # Example from logs
  # Channel where the bot posts details about tracked users who leave the server.
  leavers_channel_id: 1356610120426979399 # Example from logs

# --- Timers & Intervals ---
timers:
  # How often (in minutes) the bot automatically scans members.
  scan_interval_minutes: 60
  # How often (in minutes) the bot automatically backs up the database.
  backup_interval_minutes: 30
  # Cooldown (in hours) for the manual /gatekeeper scanlurkers command.
  scan_cooldown_hours: 1.0

# --- Message Templates ---
# Static text used in various bot messages and embeds.
messages:
  embed_footer: "Contact Staff | Gatekeeper Bot"
  embed_header: "Server Verification System"
  # Message sent via DM with /poke dm. Use {user_mention} or {user_username}.
  poke_dm_message: "Hello {user_mention}, this is a friendly reminder to complete the verification process in our server!"
  # Message sent to the gate channel with /poke gate. Use {user_mentions} (comma-separated list).
  poke_gate_message: "Attention {user_mentions}: Please complete your verification to gain access to the server."

# --- Database & Logging ---
database:
  # Path where the SQLite database file will be stored. Relative to bot.py.
  path: "data/gatekeeper.db"
  # Directory where database backups will be saved. Relative to bot.py.
  backup_dir: "data/backups"

logging:
  # Path where the log file will be stored. Relative to bot.py.
  log_file: "logs/gatekeeper.log"
  # Logging level for file and console output (DEBUG, INFO, WARNING, ERROR, CRITICAL). Use DEBUG for detailed troubleshooting.
  level: "INFO" # Change to DEBUG for verbose logs 
```

## Commands

The bot uses slash commands (`/`).

### General Commands (`/gatekeeper ...`)

*(Requires the `general_command_role_id` or `developer_role_id`)*

*   **`/gatekeeper scanlurkers`**: Manually scans all server members, updates the database based on roles (Unverified, Verified, Invalid), logs users who left, provides statistics, and creates backups. Has a cooldown defined in `config.yaml`.
*   **`/gatekeeper list status:<Invalid|Unverified>`**: Lists users currently marked as `Invalid` or `Unverified` in the database. Results are paginated and ordered by server join date (oldest first), showing join date and poke count.
*   **`/gatekeeper poke method:<gate|dm|all>`**: Sends verification reminders to all users currently marked as `Unverified`.
    *   `gate`: Pings users (in batches) in the configured `gate_channel_id`. Sends a paginated list of these users ephemerally to the command user.
    *   `dm`: Sends a configured DM to each user individually (respects rate limits).
    *   `all`: Performs both `gate` and `dm` actions.
    *   Increments the `poke_count` in the database once per user reminded per command execution. Reports success/failure statistics.

### Developer Commands (`/dev ...`)

*(Requires the `developer_role_id`)*

*   **`/dev reload`**: Safely prepares the bot for an external restart. Saves state, creates a backup, logs details, and shuts down gracefully. Requires a process manager (like `systemd`, Docker, or manual restart) to bring the bot back online.
*   **`/dev config key:<key.path> [value:<new_value>]`**: Views or *temporarily* updates configuration values at runtime (e.g., `/dev config key:timers.scan_interval_minutes value:45`). Does **not** save changes to `config.yaml` automatically. Useful for testing or temporary adjustments. Some changes may require a `/dev reload` to take full effect.
*   **`/dev saveconfig`**: Saves the *current* runtime configuration (including any temporary changes made via `/dev config`) back to the `config.yaml` file, making them permanent. Creates a backup of the old config file. Requires confirmation.
*   **`/dev healthcheck [filename:<backup_filename.db>]`**: Checks the integrity of the current database or a specified backup file (located in the `backup_dir`). Logs detailed results to the `dev_logs_channel`.
*   **`/dev restore filename:<backup_filename.db>`**: Restores the database from the specified backup file. Creates a safety backup of the current DB before restoring. Requires confirmation and a **manual bot restart** after completion. Logs details to the `dev_logs_channel`.
*   **`/dev backup`**: Manually triggers an immediate database backup with the reason "manual\_trigger".

### Help Command

*   **`/help`**: Shows a list of available commands and their descriptions based on the user's roles (General vs. Developer).

## Startup Sequence

When the bot starts, you should observe the following (visible in logs and specified channels):

1.  **Connection**: Bot connects to Discord and the SQLite database (`data/gatekeeper.db`).
2.  **Schema Init (First Run)**: If the database is new, the necessary tables and indices are created.
3.  **Command Sync**: Slash commands are registered/updated with Discord for your server.
4.  **Channel Caching**: Bot locates and verifies permissions for configured channels (General, Dev Logs, Gate, Leavers). Errors are logged if channels are missing or inaccessible.
5.  **Background Tasks Start**: Automated backup and scan tasks begin their loops.
6.  **Startup Audit**:
    *   Database integrity is checked.
    *   A data audit compares DB users vs. server members (expect discrepancies on first run).
7.  **Initial Scan**: An automatic scan runs shortly after startup, populating the database with currently unverified members.
8.  **Reporting**:
    *   A brief startup summary (success/warnings) is posted to the `general_responses_channel`.
    *   A detailed audit and scan report (including DB health, audit results, initial scan stats) is posted to the `dev_logs_channel`.

## Database Structure

The core data is stored in the `tracked_users` table within the SQLite database (`database.path`). Much of this data is unused for now - with implementations planned in future versions.

| Column                  | Type    | Description                                                                 | Default   |
| :---------------------- | :------ | :-------------------------------------------------------------------------- | :-------- |
| `user_id`               | INTEGER | Discord User ID (Primary Key)                                               |           |
| `join_date`             | TEXT    | ISO 8601 timestamp when user joined the server                              |           |
| `account_creation_date` | TEXT    | ISO 8601 timestamp when the Discord account was created                     |           |
| `username`              | TEXT    | User's Discord username#discriminator at the time of last scan              |           |
| `scan_issued_timestamp` | TEXT    | ISO 8601 timestamp when this user was last processed by a scan              | NULL      |
| `poke_count`            | INTEGER | Number of times the user has been reminded via `/poke`                      | 0         |
| `invalid_account_flag`  | BOOLEAN | `TRUE` if user lost Unverified role but has no other roles (except @everyone) | `FALSE`   |
| `unverified_account_flag`| BOOLEAN | `TRUE` if the user currently has the `unverified_role_id`                   | `TRUE`    |
| `scan_update_count`     | INTEGER | Number of times this user's record has been updated by a scan             | 0         |

**Indices:** `unverified_account_flag`, `invalid_account_flag`, `join_date`.

A `schema_version` table tracks the database structure version.

## Automatic Processes

*   **Member Join**: Automatically assigns the `unverified_role_id` and adds the new member to the database as `Unverified`.
*   **Member Leave**: Detects when a member leaves, backs up their data, logs details to `leavers_channel_id`, removes them from the database, and creates a pre-removal backup.
*   **DM Forwarding**: Forwards DMs sent to the bot to `general_responses_channel_id`, including the sender's status.
*   **Automated Scans**: Runs periodically (`scan_interval_minutes`) to update statuses based on current roles, handling verified, invalid, and left users. Creates pre/post-scan backups.
*   **Automated Backups**: Creates scheduled backups (`backup_interval_minutes`) independently of scans.

## Backup and Recovery

*   **Location**: `database.backup_dir` (default: `data/backups`).
*   **Naming**: `gatekeeper_backup_[reason]_[YYYYMMDD_HHMMSS].db`
    *   `reason`: `scheduled`, `pre_scan`, `post_scan_success`, `pre_reload`, `user_removal`, `pre_restore`, `manual_trigger`.
*   **Recovery**:
    1.  Identify the desired backup file in the backup directory.
    2.  *(Optional but Recommended)*: Use `/dev healthcheck filename:<backup_file.db>` to check its integrity.
    3.  Use `/dev restore filename:<backup_file.db>` (requires Developer role). Confirm the prompt.
    4.  **Manually restart the bot process** after the command confirms success.

## Troubleshooting

*   **Bot Offline/Not Starting**:
    *   Check `.env` for the correct token and ensure `discord_token_env` in `config.yaml` matches the variable name.
    *   Verify Python version (3.8+).
    *   Ensure all packages in `requirements.txt` are installed.
    *   Check file logs (`logs/gatekeeper.log`) for startup errors.
    *   Confirm Privileged Intents are enabled in the Discord Developer Portal.
*   **Commands Not Appearing/Working**:
    *   Ensure `guild_id` in `config.yaml` is correct.
    *   Verify the bot was invited with the `application.commands` scope.
    *   Allow Discord ~1 hour for command propagation after the first startup or major changes.
    *   Check role IDs in `config.yaml` and ensure the user has the required role (`general_command_role_id` or `developer_role_id`).
    *   Check the `dev_logs_channel` for errors related to command execution.
*   **Scans Not Updating Users Correctly**:
    *   Verify `roles.unverified_role_id` is correct.
    *   Ensure the bot has the `View Channels` and `Read Message History` permissions in relevant channels and the `Manage Roles` permission (positioned higher than the unverified role).
    *   Check `dev_logs_channel` for scan errors.
*   **Database Issues**:
    *   Run `/dev healthcheck`.
    *   Ensure the bot process has read/write permissions for the `data/` directory and the `.db` file.
    *   Consider restoring a known good backup via `/dev restore`.
*   **DM Forwarding Not Working**:
    *   Ensure the `Message Content Intent` is enabled.
    *   Verify `channels.general_responses_channel_id` is correctly set and the bot can send messages there.
*   **Enable Debug Logging**: Change `logging.level` to `DEBUG` in `config.yaml` and restart the bot for highly detailed logs (like the example provided earlier).

## Security Considerations

*   **Token Security**: Your bot token is sensitive. Store it securely using the `.env` file and do not share it.
*   **Role Permissions**: Restrict `developer_role_id` and `general_command_role_id` to trusted staff only.
*   **Data Integrity**: Automatic backups and database integrity checks help protect against data loss or corruption.
*   **Input Sanitization**: Database operations use parameterized queries (`aiosqlite` handles this) to prevent SQL injection vulnerabilities.



