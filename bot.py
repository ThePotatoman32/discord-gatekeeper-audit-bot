import discord
from discord.ext import commands, tasks
from discord import app_commands, Interaction, Member, User, Role, TextChannel, Embed, Intents, Object, ButtonStyle, AllowedMentions, InteractionMessage, Message, MessageReference
from discord.app_commands import Choice, Group

import aiosqlite
import yaml
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
from datetime import datetime, timedelta, timezone
import asyncio
import shutil
from dotenv import load_dotenv
from typing import List, Optional, Dict, Any, Union, Tuple

# --- Constants ---
CONFIG_FILE = "config.yaml"
DB_SCHEMA_VERSION = 1 # Initial version for this spec
# Status constants (implicit via flags)
# UNVERIFIED: unverified_account_flag=True, invalid_account_flag=False
# VERIFIED:   unverified_account_flag=False, invalid_account_flag=False
# INVALID:    unverified_account_flag=False, invalid_account_flag=True

# --- Configuration Loading ---
def load_config() -> Dict[str, Any]:
    """Loads the configuration from config.yaml."""
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)

        # Validate top-level keys
        required_keys = ['discord_token_env', 'guild_id', 'roles', 'channels', 'timers', 'messages', 'database', 'logging']
        if not all(key in config_data for key in required_keys):
            raise ValueError(f"Config file '{CONFIG_FILE}' missing required top-level keys: {required_keys}")

        # Validate nested keys and types (basic)
        if not config_data.get('guild_id'): raise ValueError("guild_id must be set in config.")
        config_data['guild_id'] = int(config_data['guild_id'])

        role_keys = ['general_command_role_id', 'developer_role_id', 'unverified_role_id']
        if not all(key in config_data.get('roles', {}) for key in role_keys):
             raise ValueError(f"Config roles missing required keys: {role_keys}")
        for key in role_keys:
             config_data['roles'][key] = int(config_data['roles'][key]) if config_data['roles'][key] else None
        if not config_data['roles']['unverified_role_id']:
             raise ValueError("CRITICAL: roles.unverified_role_id cannot be empty.")

        # Channel Keys
        channel_keys = ['log_channel_id', 'dm_forward_channel_id', 'gate_channel_id', 'leavers_channel_id']
        if not all(key in config_data.get('channels', {}) for key in channel_keys):
             raise ValueError(f"Config channels missing required keys: {channel_keys}")
        for key in channel_keys:
             config_data['channels'][key] = int(config_data['channels'][key]) if config_data['channels'][key] else None
        # Warning if essential channels for commands are missing
        if not config_data['channels']['log_channel_id']: logger.warning("channels.log_channel_id not set. All channel logging will fail.")
        if not config_data['channels']['dm_forward_channel_id']: logger.warning("channels.dm_forward_channel_id not set. DM forwarding and replies will fail.")
        if not config_data['channels']['gate_channel_id']: logger.warning("channels.gate_channel_id not set. /poke gate command will fail.")
        if not config_data['channels']['leavers_channel_id']: logger.warning("channels.leavers_channel_id not set. User leave events will not be logged to a channel.")


        timer_keys = ['scan_interval_minutes', 'backup_interval_minutes', 'scan_cooldown_hours']
        if not all(key in config_data.get('timers', {}) for key in timer_keys):
            raise ValueError(f"Config timers missing required keys: {timer_keys}")
        for key in timer_keys:
             if not isinstance(config_data['timers'].get(key), (int, float)) or config_data['timers'].get(key, 0) <= 0:
                 raise ValueError(f"Config timers.{key} must be a positive number.")

        message_keys = ['embed_footer', 'embed_header', 'poke_dm_message', 'poke_gate_message', 'staff_reply_prefix']
        if not all(key in config_data.get('messages', {}) for key in message_keys):
             raise ValueError(f"Config messages missing required keys: {message_keys}")
        # We don't have to error out here. For now though, let's error.

        db_keys = ['path', 'backup_dir']
        if not all(key in config_data.get('database', {}) for key in db_keys):
             raise ValueError(f"Config database missing required keys: {db_keys}")

        log_keys = ['log_file', 'level']
        if not all(key in config_data.get('logging', {}) for key in log_keys):
             raise ValueError(f"Config logging missing required keys: {log_keys}")

        # Load token key name
        if not config_data.get('discord_token_env'):
            raise ValueError("Config discord_token_env (name of env var for token) must be set.")


        return config_data
    except FileNotFoundError:
        print(f"CRITICAL ERROR: Config file '{CONFIG_FILE}' not found. Please create it based on the example/specification.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"CRITICAL ERROR: Error parsing config file '{CONFIG_FILE}': {e}")
        sys.exit(1)
    except (ValueError, TypeError, KeyError) as e:
        print(f"CRITICAL ERROR: Configuration value error or missing key: {e}")
        sys.exit(1)

# --- Logging Setup ---
def setup_logging(config: Dict[str, Any]):
    """Configures logging to console and file."""
    log_config = config.get('logging', {})
    log_level_str = log_config.get('level', 'INFO').upper()
    log_file = log_config.get('log_file', 'gatekeeper.log')

    log_level = getattr(logging, log_level_str, logging.INFO)
    log_formatter = logging.Formatter('%(asctime)s [%(levelname)-5.5s] [%(name)s] %(message)s')

    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
    file_handler.setFormatter(log_formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    # Remove default handlers if any
    for handler in root_logger.handlers[:]: root_logger.removeHandler(handler)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Set discord lib logging level
    discord_log_level = logging.INFO if log_level <= logging.INFO else logging.WARNING
    logging.getLogger('discord').setLevel(discord_log_level)
    logging.getLogger('discord.http').setLevel(logging.WARNING)
    logging.getLogger('discord.gateway').setLevel(logging.WARNING)

    return logging.getLogger("GatekeeperBot") # Return specific logger for the bot

# --- Database Management ---
class DatabaseManager:
    def __init__(self, db_path: str, backup_dir: str):
        self.db_path = db_path
        self.backup_dir = backup_dir
        self.conn: Optional[aiosqlite.Connection] = None
        self.lock = asyncio.Lock() # Guards backup/restore
        self._connection_attempts = 0
        self._max_connection_attempts = 5
        os.makedirs(self.backup_dir, exist_ok=True) # Ensure backup dir exists

    async def _connect_internal(self) -> bool:
        """Internal connect logic."""
        try:
            logger.info(f"Attempting to connect to database: {self.db_path}")
            self.conn = await aiosqlite.connect(self.db_path, timeout=15)
            await self.conn.execute("PRAGMA foreign_keys = ON;")
            await self.conn.execute("PRAGMA journal_mode=WAL;")
            await self.conn.execute("PRAGMA busy_timeout = 7500;") # Wait longer if locked
            await self.conn.commit()
            logger.info(f"Successfully connected to database: {self.db_path}")
            self._connection_attempts = 0
            return True
        except Exception as e:
            self._connection_attempts += 1
            logger.error(f"Failed to connect to database (Attempt {self._connection_attempts}/{self._max_connection_attempts}): {e}", exc_info=True)
            if self.conn: await self.conn.close(); self.conn = None
            return False

    async def connect(self):
        """Establishes connection with retry logic and initializes schema."""
        if await self._connect_internal():
            await self._initialize_schema()
        else:
            logger.critical("Initial database connection failed after multiple attempts. Exiting.")
            sys.exit(1)

    async def ensure_connection(self) -> bool:
        """Checks connection and attempts reconnect if needed."""
        if self.conn:
            try:
                # Use execute instead of fetchone for simple check
                await self.conn.execute("SELECT 1")
                return True
            except (aiosqlite.OperationalError, aiosqlite.DatabaseError, AttributeError):
                logger.warning("Database connection lost or invalid. Attempting reconnect...")
                if self.conn:
                    try: await self.conn.close()
                    except Exception: pass # Ignore errors during close if already broken
                self.conn = None
        if self._connection_attempts < self._max_connection_attempts:
            await asyncio.sleep(2 * self._connection_attempts) # Exponential backoff
            return await self._connect_internal()
        else:
            logger.error("Database reconnection failed after multiple attempts.")
            return False

    async def _initialize_schema(self):
        """Creates/migrates the database schema based on Spec 1.1."""
        if not await self.ensure_connection():
            logger.error("Cannot initialize schema: Database connection unavailable.")
            return
        async with self.conn.cursor() as cursor:
            await cursor.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)")
            await cursor.execute("SELECT version FROM schema_version")
            version_row = await cursor.fetchone()
            current_version = version_row[0] if version_row else 0

            if current_version < DB_SCHEMA_VERSION:
                logger.info(f"Initializing/Migrating database schema to Version {DB_SCHEMA_VERSION}...")
                await cursor.execute("""
                    CREATE TABLE IF NOT EXISTS tracked_users (
                        user_id INTEGER PRIMARY KEY,
                        join_date TEXT NOT NULL,
                        account_creation_date TEXT NOT NULL,
                        username TEXT NOT NULL,
                        scan_issued_timestamp TEXT,
                        poke_count INTEGER NOT NULL DEFAULT 0,
                        invalid_account_flag BOOLEAN NOT NULL DEFAULT FALSE,
                        unverified_account_flag BOOLEAN NOT NULL DEFAULT TRUE,
                        scan_update_count INTEGER NOT NULL DEFAULT 0
                    )
                """)
                # Indices
                await cursor.execute("CREATE INDEX IF NOT EXISTS idx_tracked_users_unverified ON tracked_users(unverified_account_flag)")
                await cursor.execute("CREATE INDEX IF NOT EXISTS idx_tracked_users_invalid ON tracked_users(invalid_account_flag)")
                await cursor.execute("CREATE INDEX IF NOT EXISTS idx_tracked_users_join_date ON tracked_users(join_date)")

                # Update version atomically
                await cursor.execute("DELETE FROM schema_version") # Remove old version first
                await cursor.execute(f"INSERT INTO schema_version (version) VALUES ({DB_SCHEMA_VERSION})")
                logger.info(f"Database schema Version {DB_SCHEMA_VERSION} initialized/updated.")

            await self.conn.commit()

    async def close(self):
        """Closes the database connection."""
        if self.conn:
            try:
                await self.conn.close()
                self.conn = None
                logger.info("Database connection closed.")
            except Exception as e:
                logger.error(f"Error closing database connection: {e}", exc_info=True)
                self.conn = None # Ensure it's marked as closed

    async def _execute_wrapper(self, query: str, params: tuple = ()):
        """Wrapper for execute with connection check."""
        if not await self.ensure_connection(): raise aiosqlite.OperationalError("Database connection unavailable.")
        try:
            async with self.conn.cursor() as cursor:
                await cursor.execute(query, params)
                await self.conn.commit()
            return cursor.rowcount
        except aiosqlite.Error as e:
            logger.error(f"Database write error executing '{query[:100]}...': {e}", exc_info=True)
            raise # Re-raise the specific DB error
        except Exception as e:
            logger.error(f"Unexpected error during DB write '{query[:100]}...': {e}", exc_info=True)
            raise # Re-raise other errors

    async def _fetch_wrapper(self, query: str, params: tuple = (), fetch_all: bool = False):
        """Wrapper for fetch with connection check."""
        if not await self.ensure_connection(): raise aiosqlite.OperationalError("Database connection unavailable.")
        try:
            async with self.conn.cursor() as cursor:
                await cursor.execute(query, params)
                return await cursor.fetchall() if fetch_all else await cursor.fetchone()
        except aiosqlite.Error as e:
            logger.error(f"Database fetch error executing '{query[:100]}...': {e}", exc_info=True)
            raise # Re-raise the specific DB error
        except Exception as e:
            logger.error(f"Unexpected error during DB fetch '{query[:100]}...': {e}", exc_info=True)
            raise # Re-raise other errors

    # --- Specific Data Operations ---

    async def add_or_update_unverified_user(self, user_id: int, username: str, join_date: datetime, account_creation_date: datetime):
        """Adds/updates a user found with the unverified role during scan."""
        now_iso = datetime.now(timezone.utc).isoformat()
        join_date_iso = join_date.isoformat()
        account_creation_date_iso = account_creation_date.isoformat()

        query = """
            INSERT INTO tracked_users (user_id, username, join_date, account_creation_date, unverified_account_flag, invalid_account_flag, scan_issued_timestamp, scan_update_count)
            VALUES (?, ?, ?, ?, TRUE, FALSE, ?, 1)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                join_date = excluded.join_date,
                account_creation_date = excluded.account_creation_date,
                unverified_account_flag = TRUE,
                invalid_account_flag = FALSE,
                scan_issued_timestamp = excluded.scan_issued_timestamp,
                scan_update_count = scan_update_count + 1
            WHERE tracked_users.user_id = excluded.user_id -- Ensure we only update the matched user
        """
        params = (user_id, username, join_date_iso, account_creation_date_iso, now_iso)
        await self._execute_wrapper(query, params)
        logger.debug(f"Added/Updated user {username} ({user_id}) as unverified.")

    async def update_user_flags(self, user_id: int, unverified: bool, invalid: bool):
        """Sets the verification flags for a user."""
        now_iso = datetime.now(timezone.utc).isoformat()
        query = "UPDATE tracked_users SET unverified_account_flag = ?, invalid_account_flag = ?, scan_issued_timestamp = ?, scan_update_count = scan_update_count + 1 WHERE user_id = ?"
        params = (unverified, invalid, now_iso, user_id)
        await self._execute_wrapper(query, params)
        status = "verified" if not unverified and not invalid else ("invalid" if invalid else "unverified")
        logger.debug(f"Updated flags for user {user_id} to: {status}")

    async def increment_poke_count(self, user_ids: List[int]):
        """Increments the poke count for a list of users."""
        if not user_ids: return 0
        # Ensure user_ids are integers to prevent potential issues
        safe_user_ids = [int(uid) for uid in user_ids]
        placeholders = ','.join('?' * len(safe_user_ids))
        query = f"UPDATE tracked_users SET poke_count = poke_count + 1 WHERE user_id IN ({placeholders})"
        params = tuple(safe_user_ids)
        return await self._execute_wrapper(query, params)

    async def get_user(self, user_id: int) -> Optional[tuple]:
        """Gets a specific user's data."""
        return await self._fetch_wrapper("SELECT * FROM tracked_users WHERE user_id = ?", (user_id,))

    async def get_users_by_flag(self, flag_name: str, sort_by: str = 'join_date', order: str = 'ASC') -> List[tuple]:
        """Gets users by flag status, sorted."""
        if flag_name not in ['unverified_account_flag', 'invalid_account_flag']:
             raise ValueError("Invalid flag name")
        valid_sorts = ['user_id', 'join_date', 'account_creation_date', 'username', 'scan_issued_timestamp', 'poke_count', 'scan_update_count']
        valid_orders = ['ASC', 'DESC']
        sort_by = sort_by if sort_by in valid_sorts else 'join_date'
        order = order.upper() if order.upper() in valid_orders else 'ASC'

        query = f"SELECT * FROM tracked_users WHERE {flag_name} = TRUE ORDER BY {sort_by} {order}"
        return await self._fetch_wrapper(query, (), fetch_all=True)

    async def get_all_tracked_ids(self) -> List[int]:
        """Gets all user IDs currently tracked."""
        rows = await self._fetch_wrapper("SELECT user_id FROM tracked_users", fetch_all=True)
        return [row[0] for row in rows] if rows else []

    async def remove_user(self, user_id: int) -> Optional[tuple]:
        """Removes a user from the database and returns their data. Performs backup first."""
        user_data = await self.get_user(user_id)
        if user_data:
            await self.backup(reason="user_removal") # Backup before removing
            await self._execute_wrapper("DELETE FROM tracked_users WHERE user_id = ?", (user_id,))
            logger.info(f"Removed user {user_id} from database.")
            return user_data
        return None

    async def get_stats(self) -> Dict[str, int]:
        """Gathers statistics based on flags."""
        stats = {'total': 0, 'unverified': 0, 'invalid': 0, 'verified': 0}
        rows = await self._fetch_wrapper("SELECT unverified_account_flag, invalid_account_flag, COUNT(*) FROM tracked_users GROUP BY unverified_account_flag, invalid_account_flag", fetch_all=True)
        if not rows: return stats
        total = 0
        for unverified, invalid, count in rows:
            total += count
            if unverified: stats['unverified'] += count
            elif invalid: stats['invalid'] += count
            else: stats['verified'] += count
        stats['total'] = total
        return stats

    # --- Backup & Restore ---
    async def backup(self, reason: str = "scheduled") -> Optional[str]:
        """Creates a backup of the database file."""
        if not await self.ensure_connection():
            logger.error("Cannot backup: Database connection unavailable.")
            return None

        async with self.lock:
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_filename = f"gatekeeper_backup_{reason}_{timestamp}.db"
                backup_path = os.path.join(self.backup_dir, backup_filename)

                # Checkpoint WAL before copy
                logger.debug("Attempting WAL checkpoint before backup...")
                await self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                await self.conn.commit()
                logger.debug("WAL checkpoint successful.")

                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, shutil.copy2, self.db_path, backup_path)

                logger.info(f"Database backup ({reason}) created successfully: {backup_path}")
                return backup_path
            except Exception as e:
                logger.error(f"Database backup ({reason}) failed: {e}", exc_info=True)
                try:
                     # Attempt to resume checkpointing if truncate failed
                     if self.conn and not self.conn.is_closed(): # type: ignore[attr-defined] # Check if connection object exists and isn't closed
                         await self.conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
                except Exception as cp_err:
                     logger.error(f"Failed to reset WAL checkpoint mode after backup error: {cp_err}")
                return None

    async def restore(self, backup_filename: str) -> bool:
         """Restores the database from a backup file. Requires bot restart."""
         backup_filepath = os.path.join(self.backup_dir, backup_filename)
         if not os.path.exists(backup_filepath):
            logger.error(f"Restore failed: Backup file not found at {backup_filepath}")
            return False

         async with self.lock:
            logger.warning(f"Attempting database restore from {backup_filename}. Bot must be restarted after this.")
            # Backup current DB before overwriting
            pre_restore_backup_path = await self.backup(reason="pre_restore")
            if not pre_restore_backup_path:
                 logger.error("Restore failed: Could not create pre-restore backup.")
                 return False
            logger.info(f"Created pre-restore backup: {os.path.basename(pre_restore_backup_path)}")

            await self.close() # Close current connection

            try:
                # Copy the backup file to the original path
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, shutil.copy2, backup_filepath, self.db_path)
                logger.info(f"Database successfully restored from {backup_filename} to {self.db_path}.")
                logger.critical("DATABASE RESTORED. PLEASE RESTART THE BOT NOW.")
                # Don't reconnect here, force manual restart
                return True
            except Exception as e:
                logger.error(f"Database restore failed during copy: {e}", exc_info=True)
                # Attempt to restore the pre-restore backup
                logger.warning("Attempting to roll back restore using pre-restore backup...")
                try:
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, shutil.copy2, pre_restore_backup_path, self.db_path)
                    logger.info("Successfully rolled back restore using pre-restore backup.")
                except Exception as rollback_err:
                     logger.error(f"CRITICAL: Failed to roll back restore: {rollback_err}. Manual intervention may be required using backup: {pre_restore_backup_path}")
                # Attempt to reconnect after rollback failure or success
                await self.connect() # Try to get back to a working state if possible
                return False

    async def health_check(self, db_filepath: Optional[str] = None) -> Tuple[bool, str]:
        """Performs an integrity check on the current or a specified DB file."""
        target_db = db_filepath or self.db_path
        if not os.path.exists(target_db):
            return False, f"Error: Database file not found at {target_db}"

        temp_conn = None
        try:
            # Connect directly to the target file for check
            logger.debug(f"Performing integrity check on: {target_db}")
            temp_conn = await aiosqlite.connect(target_db, timeout=10)
            async with temp_conn.cursor() as cursor:
                await cursor.execute("PRAGMA integrity_check;")
                result = await cursor.fetchone()
            await temp_conn.close()
            temp_conn = None # Ensure it's None after close

            if result and result[0].lower() == 'ok':
                logger.info(f"Integrity check passed for {os.path.basename(target_db)}")
                return True, f"Database integrity check passed for '{os.path.basename(target_db)}'."
            else:
                logger.warning(f"Integrity check failed for {os.path.basename(target_db)}: {result[0] if result else 'Unknown error'}")
                return False, f"Database integrity check failed for '{os.path.basename(target_db)}': {result[0] if result else 'Unknown error'}"
        except Exception as e:
            if temp_conn:
                try: await temp_conn.close()
                except Exception: pass
            logger.error(f"Database health check failed for {target_db}: {e}", exc_info=True)
            return False, f"Error during health check for '{os.path.basename(target_db)}': {e}"

    async def audit_data(self, guild: discord.Guild) -> Tuple[str, List[str]]:
        """Compares DB users with Guild members, returns summary and discrepancies."""
        if not await self.ensure_connection():
            return "Error: Database connection unavailable.", []

        discrepancies = []
        try:
            db_ids = set(await self.get_all_tracked_ids())
            logger.debug(f"Audit: Found {len(db_ids)} users in DB.")

            server_member_ids = set()
            fetched_count = 0
            async for member in guild.fetch_members(limit=None):
                if not member.bot:
                    server_member_ids.add(member.id)
                fetched_count += 1
                if fetched_count % 500 == 0: logger.debug(f"Audit: Fetched {fetched_count} members...")
            logger.debug(f"Audit: Fetched {fetched_count} total members, {len(server_member_ids)} non-bot members.")


            # Find users in DB but not in server? They probably left the server
            left_users = db_ids - server_member_ids
            if left_users:
                discrepancies.append(f"Found {len(left_users)} users in DB but not in Server (should be removed): {list(left_users)}")
                logger.warning(f"Audit Discrepancy: Users in DB but not server: {left_users}")

            # Find users in server but not in DB. 
            missed_users = server_member_ids - db_ids
            # This is expected if they are verified and never had the unverified role
            # Let's check if any missed users HAVE the unverified role
            unverified_role_id = config['roles']['unverified_role_id']
            unverified_role = guild.get_role(unverified_role_id) if unverified_role_id else None
            missed_unverified = []
            if unverified_role:
                 for user_id in missed_users:
                     member = guild.get_member(user_id) # Use get_member (cache) first for efficiency
                     if not member:
                         try: member = await guild.fetch_member(user_id) # Fetch if not cached
                         except discord.NotFound: continue # User might have left between fetch_members and here
                         except discord.HTTPException as e:
                             logger.warning(f"Audit: Failed to fetch member {user_id} during missed check: {e}")
                             continue

                     if member and unverified_role in member.roles:
                         missed_unverified.append(user_id)

            if missed_unverified:
                discrepancies.append(f"Found {len(missed_unverified)} users with Unverified role in Server but NOT in DB (should be added): {missed_unverified}")
                logger.warning(f"Audit Discrepancy: Unverified users in server but not DB: {missed_unverified}")

            summary = f"DB Users: {len(db_ids)}, Server Members (non-bot): {len(server_member_ids)}. Discrepancies Found: {len(discrepancies)}."
            return summary, discrepancies

        except discord.HTTPException as e:
            logger.error(f"Audit failed due to Discord API error: {e}")
            return f"Error: Discord API error during audit: {e}", []
        except Exception as e:
            logger.error(f"Audit failed: {e}", exc_info=True)
            return f"Error during data audit: {e}", []


# --- Bot Implementation ---
class GatekeeperBot(commands.Bot):
    def __init__(self, config: Dict[str, Any], db_manager: DatabaseManager):
        intents = Intents.default()
        intents.members = True # Required for member events and fetching
        intents.message_content = True # Required for DM reading and replies

        super().__init__(command_prefix=commands.when_mentioned_or("!gk "), intents=intents) # Prefix mostly unused, maybe for future testing
        self.config = config
        self.db = db_manager
        self.guild_id = config['guild_id']
        self.guild: Optional[discord.Guild] = None
        self.scan_in_progress = asyncio.Lock()
        # Channel objects (cached on_ready)
        self.log_channel: Optional[TextChannel] = None
        self.dm_forward_channel: Optional[TextChannel] = None
        self.gate_channel: Optional[TextChannel] = None
        self.leavers_channel: Optional[TextChannel] = None

    async def setup_hook(self):
        """Prepare the bot: connect DB, start tasks, sync commands."""
        logger.info("Running setup_hook...")
        await self.db.connect() # Connect DB

        # Add command groups, I should really start using cogs from the beginning...
        self.tree.add_command(AdminCommands(self), guild=Object(id=self.guild_id))
        self.tree.add_command(DevCommands(self), guild=Object(id=self.guild_id))
        self.tree.add_command(help_command, guild=Object(id=self.guild_id)) # Add top-level help

        # Sync commands
        guild_obj = Object(id=self.guild_id)
        # self.tree.copy_global_to(guild=guild_obj) # Maybe needed? Seems ok without, but keeping this here anyway.
        try:
            synced_commands = await self.tree.sync(guild=guild_obj)
            logger.info(f"Synced {len(synced_commands)} slash commands to guild {self.guild_id}.")
        except discord.HTTPException as e:
            logger.error(f"Failed to sync slash commands: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error during command sync: {e}", exc_info=True)


        # Start background tasks AFTER setup is mostly done
        self.auto_backup_task.start()
        self.auto_scan_task.start()
        logger.info("Background tasks initiated.")


    async def on_ready(self):
        """Called when the bot is fully connected and ready."""
        logger.info(f'Logged in as {self.user.name} ({self.user.id})')
        logger.info(f'discord.py version: {discord.__version__}')

        self.guild = self.get_guild(self.guild_id)
        if not self.guild:
            logger.critical(f"Could not find Guild with ID {self.guild_id}. Check config. Bot cannot operate.")
            await self.close() # Exit if guild not found
            return

        logger.info(f'Operating on server: {self.guild.name} ({self.guild.id})')
        await self.change_presence(activity=discord.Game(name="Watching the gates"))

        # Cache channel objects
        self.log_channel = self._get_channel_safe(self.config['channels']['log_channel_id'], 'Log')
        self.dm_forward_channel = self._get_channel_safe(self.config['channels']['dm_forward_channel_id'], 'DM Forward')
        self.gate_channel = self._get_channel_safe(self.config['channels']['gate_channel_id'], 'Gate')
        self.leavers_channel = self._get_channel_safe(self.config['channels']['leavers_channel_id'], 'Leavers')

        # Perform startup audit and initial scan
        await self.perform_startup_audit()

    def _get_channel_safe(self, channel_id: Optional[int], channel_name: str) -> Optional[TextChannel]:
        """Safely gets and validates a channel."""
        if not channel_id:
            logger.warning(f"{channel_name} channel ID not configured.")
            return None
        if not self.guild:
            logger.error(f"Cannot get {channel_name} channel: Guild object is not available.")
            return None

        channel = self.guild.get_channel(channel_id)
        if isinstance(channel, TextChannel):
            # Can we send messages?
            my_perms = channel.permissions_for(self.guild.me)
            missing_perms = []
            if not my_perms.send_messages: missing_perms.append("Send Messages")
            if not my_perms.embed_links: missing_perms.append("Embed Links")
            # Can we do other stuff we need to do?
            if channel_id == self.config['channels'].get('dm_forward_channel_id'):
                 if not my_perms.read_message_history: missing_perms.append("Read Message History (for DM replies)")
                 if not my_perms.add_reactions: missing_perms.append("Add Reactions (for DM reply feedback)")

            if not missing_perms:
                 logger.info(f"Successfully located {channel_name} channel: #{channel.name} ({channel.id})")
                 return channel
            else:
                 logger.error(f"Located {channel_name} channel #{channel.name} ({channel_id}), but **MISSING PERMISSIONS**: {', '.join(missing_perms)}.")
                 return None # Treat as unusable if permissions missing
        elif channel:
            logger.error(f"Configured {channel_name} channel ID {channel_id} (#{channel.name}) is not a Text Channel.")
            return None
        else:
            logger.error(f"Configured {channel_name} channel ID {channel_id} was not found in the server.")
            return None

    async def perform_startup_audit(self):
        """Performs startup checks, initial scan, and logging."""
        logger.info("Performing startup audit...")
        startup_log_msgs = ["Bot startup sequence initiated."]
        errors_found = False

        # 1. DB Health Check
        db_ok, db_msg = await self.db.health_check()
        startup_log_msgs.append(f"Database Health: {db_msg}")
        if not db_ok: errors_found = True; startup_log_msgs.append("⚠️ Database integrity check failed.")
        else: startup_log_msgs.append("✔️ Database integrity check passed.")

        # 2. Data Audit (Compare DB vs Server)
        audit_summary, discrepancies = await self.db.audit_data(self.guild)
        startup_log_msgs.append(f"Data Audit: {audit_summary}")
        if discrepancies:
             errors_found = True
             startup_log_msgs.append(f"⚠️ Data audit found {len(discrepancies)} discrepancies:")
             startup_log_msgs.extend([f"  - {d}" for d in discrepancies])
        else: startup_log_msgs.append("✔️ Data audit found no major discrepancies.")

        # 3. Initial Scan (Trigger /scanlurkers logic)
        startup_log_msgs.append("Performing initial user scan...")
        try:
            # Use a lock to prevent conflict if auto-scan starts immediately
            if not self.scan_in_progress.locked():
                # Pass None for interaction, as this is not command-invoked
                scan_summary = await self.perform_scan(invoked_by="Startup Audit", interaction=None)
                scan_summary_str = ", ".join([f"{k}: {v}" for k, v in scan_summary.items()])
                startup_log_msgs.append(f"Initial Scan Summary: {scan_summary_str}")
                startup_log_msgs.append(f"✔️ Initial user scan completed ({scan_summary.get('checked', 0)} members checked).")
            else:
                 startup_log_msgs.append("Initial scan skipped: Another scan was already in progress.")
                 startup_log_msgs.append("⚠️ Initial scan skipped (already running).")
                 errors_found = True # Indicate potential issue
        except Exception as e:
            logger.error(f"Startup scan failed: {e}", exc_info=True)
            startup_log_msgs.append(f"ERROR during initial scan: {e}")
            startup_log_msgs.append("❌ Initial user scan failed.")
            errors_found = True

        # 4. Timer Status
        startup_log_msgs.append(f"Auto Scan Interval: {self.config['timers']['scan_interval_minutes']} minutes.")
        startup_log_msgs.append(f"Auto Backup Interval: {self.config['timers']['backup_interval_minutes']} minutes.")

        # 5. Log Results to Consolidated Log Channel
        if self.log_channel:
             embed_log = Embed(
                 title="🤖 Bot Startup Audit & Scan Report",
                 description="\n".join(startup_log_msgs)[:4000], # Limit description length
                 color=discord.Color.red() if errors_found else discord.Color.blue(),
                 timestamp=datetime.now(timezone.utc)
             )
             embed_log.set_footer(text=self.config['messages']['embed_footer'])
             await self._log_embed_to_channel(self.log_channel, embed_log, "Startup Audit")
        else: logger.warning("Log channel not available, skipping detailed startup report.")

        logger.info("Startup audit complete.")


    # --- Background Tasks ---
    @tasks.loop(minutes=load_config()['timers']['backup_interval_minutes'])
    async def auto_backup_task(self):
        """Periodically backs up the database."""
        logger.info("Starting automatic database backup...")
        backup_path = await self.db.backup(reason="scheduled")
        if backup_path: logger.info(f"Automatic database backup successful: {backup_path}")
        else:
            logger.error("Automatic database backup failed.")
            await self._log_to_channel(self.log_channel, "🚨 Automatic Database Backup Failed!", level=logging.ERROR)

    @tasks.loop(minutes=load_config()['timers']['scan_interval_minutes'])
    async def auto_scan_task(self):
        """Periodically scans the server."""
        if not self.guild or self.scan_in_progress.locked():
            logger.debug("Auto-scan skipped: Guild not available or scan already in progress.")
            return

        logger.info("Starting automatic member scan...")
        try:
            summary = await self.perform_scan(invoked_by="Auto-Task", interaction=None)
            logger.info(f"Automatic scan finished. Summary: {summary}")
            # Log detailed summary to the main log channel
            duration_placeholder = 0 # Not currently implemented, will add this eventually
            scan_success = summary.get("errors", 1) == 0 # Assume error if key missing

            log_embed = Embed(title="⚙️ Auto-Scan Completed", timestamp=datetime.now(timezone.utc))
            log_embed.add_field(name="Invoked By", value="Auto-Task", inline=False)
            log_embed.add_field(name="Duration", value=f"~N/A TO DO", inline=False) # Placeholder
            summary_text = "\n".join([f"- {key.replace('_', ' ').capitalize()}: {value}" for key, value in summary.items()])
            log_embed.add_field(name="Summary", value=summary_text, inline=False)
            log_embed.color = discord.Color.blue() if scan_success else discord.Color.orange()

            await self._log_embed_to_channel(self.log_channel, log_embed, "Auto-Scan Summary")

        except Exception as e:
            logger.error(f"Error during automatic scan: {e}", exc_info=True)
            await self._log_to_channel(self.log_channel, f"🚨 Automatic Scan Failed: {e}", level=logging.ERROR)

    @auto_backup_task.before_loop
    @auto_scan_task.before_loop
    async def before_tasks(self):
        """Wait until the bot is ready."""
        await self.wait_until_ready()
        logger.info("Bot ready, starting background tasks.")

    # --- Core Scan Logic ---
    async def perform_scan(self, invoked_by: str, interaction: Optional[Interaction]) -> Dict[str, int]:
        """Scans members, updates database based on roles, returns summary."""
        if not self.guild: raise RuntimeError("Guild not available for scan")

        # Use lock AFTER interaction response/deferral if applicable
        if self.scan_in_progress.locked():
            raise RuntimeError("Scan already in progress. Please wait.")

        async with self.scan_in_progress:
            logger.info(f"Scan initiated by: {invoked_by}")
            start_time = datetime.now(timezone.utc)
            summary = {"checked": 0, "added_unverified": 0, "updated_to_unverified": 0, "marked_verified": 0, "marked_invalid": 0, "removed_left": 0, "errors": 0}
            scan_success = False
            progress_message: Optional[InteractionMessage] = None
            # Determine ephemeral status based on invoker (only dev commands are ephemeral)
            is_dev_command = interaction is not None and interaction.command is not None and interaction.command.parent and interaction.command.parent.name == "dev"
            ephemeral_status = is_dev_command # True for /dev commands, False otherwise

            # 1. Backup BEFORE scan
            backup_path = await self.db.backup(reason="pre_scan")
            if not backup_path:
                logger.error("Scan aborted: Failed to create pre-scan backup.")
                await self._log_to_channel(self.log_channel, "🚨 Scan Aborted: Failed pre-scan backup.", level=logging.ERROR)
                # Use ephemeral status for followup
                if interaction: await interaction.followup.send("❌ Scan aborted: Failed to create pre-scan backup.", ephemeral=ephemeral_status)
                raise RuntimeError("Failed pre-scan backup.") # Stop scan

            logger.info(f"Pre-scan backup created: {os.path.basename(backup_path)}")
            pre_scan_backup_filename = os.path.basename(backup_path) # Store filename for potential restore msg

            # Send initial progress message if invoked by command
            if interaction:
                 try:
                     # Use ephemeral status
                     progress_message = await interaction.followup.send("⏳ Scan starting... Fetching members...", ephemeral=ephemeral_status)
                 except Exception as e: logger.error(f"Failed to send initial progress message: {e}")


            # 2. Get Roles and Members
            unverified_role_id = self.config['roles']['unverified_role_id']
            unverified_role = self.guild.get_role(unverified_role_id)
            if not unverified_role:
                msg = f"Scan failed: Unverified role ID {unverified_role_id} not found."
                logger.critical(msg)
                await self._log_to_channel(self.log_channel, f"🚨 {msg}", level=logging.CRITICAL)
                # Use ephemeral status
                if interaction and progress_message: await progress_message.edit(content=f"❌ {msg}")
                elif interaction: await interaction.followup.send(f"❌ {msg}", ephemeral=ephemeral_status)
                raise ValueError(msg)

            try:
                logger.debug("Fetching all guild members...")
                members_list = [m async for m in self.guild.fetch_members(limit=None)]
                members = {m.id: m for m in members_list if not m.bot} # Dict for faster lookup, ignore bots
                member_count = len(members)
                logger.debug(f"Fetched {member_count} non-bot members.")
                summary["checked"] = member_count

                # Use ephemeral status
                if interaction and progress_message:
                    await progress_message.edit(content=f"⏳ Scanning {member_count} members...")

                db_user_ids = set(await self.db.get_all_tracked_ids())
                current_member_ids = set(members.keys())
                processed_count = 0

                # 3. Iterate and Update DB
                for user_id, member in members.items():
                    processed_count += 1
                    has_unverified_role = unverified_role in member.roles
                    # Check for ANY other role besides @everyone and the unverified role
                    has_other_role = any(r != self.guild.default_role and r != unverified_role for r in member.roles)
                    user_in_db = user_id in db_user_ids

                    try:
                        if has_unverified_role:
                            # Store/Update as unverified
                            await self.db.add_or_update_unverified_user(
                                user_id=user_id, username=str(member),
                                join_date=member.joined_at or start_time, # Use scan time if join date missing
                                account_creation_date=member.created_at
                            )
                            if user_in_db: summary["updated_to_unverified"] += 1
                            else: summary["added_unverified"] += 1
                        else:
                            # User does NOT have the unverified role
                            if user_in_db: # Only update if they were previously tracked
                                if has_other_role:
                                    # Mark as verified (unverified=False, invalid=False)
                                    await self.db.update_user_flags(user_id, unverified=False, invalid=False)
                                    summary["marked_verified"] += 1
                                else:
                                    # Mark as invalid (unverified=False, invalid=True)
                                    # Check if they *only* have @everyone
                                    is_truly_invalid = len(member.roles) == 1 and member.roles[0] == self.guild.default_role
                                    if is_truly_invalid:
                                        await self.db.update_user_flags(user_id, unverified=False, invalid=True)
                                        summary["marked_invalid"] += 1
                                    else:
                                        # They lost unverified but gained some OTHER role(s) -> Verified
                                        await self.db.update_user_flags(user_id, unverified=False, invalid=False)
                                        summary["marked_verified"] += 1

                            # Else: User not in DB and not unverified -> ignore

                    except Exception as db_err:
                         logger.error(f"Scan: DB error processing user {user_id} ({member.name}): {db_err}", exc_info=True)
                         summary["errors"] += 1

                    # Update progress indicator periodically
                    if interaction and progress_message and processed_count % 50 == 0: # Update every 50 users
                        try:
                            await progress_message.edit(content=f"⏳ Scanning... {processed_count}/{member_count} members ({processed_count/member_count*100:.1f}%)")
                            await asyncio.sleep(0.5) # Prevent rate limits on edits
                        except discord.HTTPException: pass # Ignore if edit fails
                        except Exception as e: logger.warning(f"Failed to update progress message: {e}")


                # 4. Check for users who left
                left_user_ids = db_user_ids - current_member_ids
                for user_id in left_user_ids:
                     # Use the main remove function which includes backup and logging
                     await self.handle_user_leave(user_id, reason="Detected during scan")
                     summary["removed_left"] += 1

                scan_success = summary["errors"] == 0 # Mark success if no errors during processing

            except discord.HTTPException as api_err:
                 logger.error(f"Scan failed due to Discord API error: {api_err}", exc_info=True)
                 summary["errors"] += 1
                 await self._log_to_channel(self.log_channel, f"🚨 Scan Error (API): {api_err}", level=logging.ERROR)
                 # Use ephemeral status
                 if interaction and progress_message: await progress_message.edit(content=f"❌ Scan failed (API Error): {api_err}")
                 elif interaction: await interaction.followup.send(f"❌ Scan failed (API Error): {api_err}", ephemeral=ephemeral_status)

            except Exception as e:
                 logger.error(f"Unexpected error during scan: {e}", exc_info=True)
                 summary["errors"] += 1
                 await self._log_to_channel(self.log_channel, f"🚨 Scan Error (Internal): {e}", level=logging.ERROR)
                 # Use ephemeral status
                 if interaction and progress_message: await progress_message.edit(content=f"❌ Scan failed (Internal Error): {e}")
                 elif interaction: await interaction.followup.send(f"❌ Scan failed (Internal Error): {e}", ephemeral=ephemeral_status)

            # --- 5. Post-Scan Actions ---
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            logger.info(f"Scan finished in {duration:.2f} seconds. Success: {scan_success}. Summary: {summary}")

            # Create detailed log embed
            log_embed = Embed(title="🛠️ Detailed Scan Log", timestamp=end_time)
            log_embed.add_field(name="Invoked By", value=invoked_by, inline=False)
            log_embed.add_field(name="Duration", value=f"{duration:.2f} seconds", inline=False)

            summary_text = "\n".join([f"- {key.replace('_', ' ').capitalize()}: {value}" for key, value in summary.items()])
            log_embed.add_field(name="Summary", value=summary_text, inline=False)

            if scan_success:
                log_embed.color = discord.Color.green()
                log_embed.title = "✅ Detailed Scan Log (Success)"

                # Backup on success
                post_scan_backup = await self.db.backup(reason="post_scan_success")
                if post_scan_backup:
                    log_embed.add_field(name="Backup", value=f"Post-scan backup created: `{os.path.basename(post_scan_backup)}`", inline=False)
                else:
                    log_embed.add_field(name="Backup", value="⚠️ Failed to create post-scan backup!", inline=False)
                    log_embed.color = discord.Color.orange() # Indicate warning

            else: # Scan failed or had errors
                log_embed.color = discord.Color.red()
                log_embed.title = "❌ Detailed Scan Log (Failure/Errors)"
                log_embed.description = f"Scan encountered {summary['errors']} errors. Check details below." # Description added before fields

                # Restore Prompt (only if invoked by interaction)
                if interaction:
                    logger.warning(f"Scan failed. Prompting {interaction.user} for restore from {pre_scan_backup_filename}.")
                    confirm_view = ConfirmView(interaction.user.id, timeout=120.0)
                    msg_content = (f"❌ Scan failed or had errors.\n"
                                   f"Do you want to attempt restoring the database from the pre-scan backup (`{pre_scan_backup_filename}`)?\n"
                                   f"**WARNING: This requires a manual bot restart after restore.**")
                    # Send confirmation to the user who initiated
                    confirm_message = await interaction.followup.send(msg_content, view=confirm_view, ephemeral=ephemeral_status)
                    confirm_view.message = confirm_message # Assign message for timeout editing
                    await confirm_view.wait()

                    restore_attempted = False
                    restore_success = False
                    if confirm_view.confirmed:
                         restore_attempted = True
                         logger.info(f"User {interaction.user} confirmed restore from {pre_scan_backup_filename}.")
                         # Edit the confirmation message
                         await interaction.edit_original_response(content=f"⏳ Attempting restore from `{pre_scan_backup_filename}`...", view=None)
                         restore_success = await self.db.restore(pre_scan_backup_filename)
                         result_msg = f"✅ Restore successful. **RESTART BOT NOW**." if restore_success else f"❌ Restore failed. Check logs. Current DB state might be inconsistent."
                         await interaction.edit_original_response(content=result_msg, view=None)
                    elif confirm_view.confirmed is False: # Explicit cancel
                         await interaction.edit_original_response(content="Restore cancelled. Database remains in its current state.", view=None)
                    # Timeout handled by view

                    log_embed.add_field(name="Restore Attempt", value=f"User prompted for restore: {'Yes' if restore_attempted else 'No'}\nConfirmed: {'Yes' if confirm_view.confirmed else ('No' if confirm_view.confirmed is False else 'Timed Out')}\nRestore Success: {'Yes' if restore_success else ('No' if restore_attempted else 'N/A')}", inline=False)


            # Send Detailed Embed to Log Channel
            await self._log_embed_to_channel(self.log_channel, log_embed, "Detailed Scan Log")

            # Update interaction message if it exists
            if interaction and progress_message:
                 final_msg = "✅ Scan Complete." if scan_success else "❌ Scan Failed or Had Errors."
                 try: await progress_message.edit(content=final_msg, view=None)
                 except: pass # Ignore errors editing final message
            elif interaction and not progress_message: # If initial progress message failed, send a final status
                 final_msg = "✅ Scan Complete." if scan_success else "❌ Scan Failed or Had Errors."
                 try: await interaction.followup.send(final_msg, ephemeral=ephemeral_status)
                 except: pass

            return summary # Return summary dict

    # --- Event Handlers ---
    @commands.Cog.listener()
    async def on_member_join(self, member: Member):
        """Handle member joining - assign unverified role."""
        if member.guild.id != self.guild_id or member.bot: return

        logger.info(f"Member joined: {member} ({member.id})")
        unverified_role_id = self.config['roles']['unverified_role_id']
        unverified_role = self.guild.get_role(unverified_role_id)

        if not unverified_role:
            logger.error(f"Cannot process join for {member.id}: Unverified role {unverified_role_id} not found.")
            await self._log_to_channel(self.log_channel, f"🚨 Error processing join for {member.mention}: Unverified role ID `{unverified_role_id}` not found.", level=logging.ERROR)
            return

        try:
            await member.add_roles(unverified_role, reason="New member join")
            logger.info(f"Assigned unverified role to {member.id}")
            # Add to DB immediately as unverified
            await self.db.add_or_update_unverified_user(
                user_id=member.id, username=str(member),
                join_date=member.joined_at or datetime.now(timezone.utc),
                account_creation_date=member.created_at
            )
            await self._log_to_channel(self.log_channel, f"✅ Assigned unverified role to {member.mention} and added to database.", level=logging.INFO)
        except discord.Forbidden:
            logger.error(f"Failed to assign unverified role to {member.id}: Missing Permissions.")
            await self._log_to_channel(self.log_channel, f"🚨 Permission Error on Join: Cannot assign unverified role to {member.mention}. Check role hierarchy/permissions.", level=logging.ERROR)
        except Exception as e:
            logger.error(f"Error processing member join {member.id}: {e}", exc_info=True)
            await self._log_to_channel(self.log_channel, f"🚨 Error processing join for {member.mention}: {e}", level=logging.ERROR)

    @commands.Cog.listener()
    async def on_member_remove(self, member: Member):
        """Handle member leaving."""
        if member.guild.id != self.guild_id or member.bot: return
        logger.info(f"Member left: {member} ({member.id})")
        await self.handle_user_leave(member.id, reason="Detected member leave event", member_object=member)


    async def handle_user_leave(self, user_id: int, reason: str, member_object: Optional[Union[Member, User]] = None):
        """Shared logic for handling user removal from DB and logging."""
        # 1. Check DB and Get Data (remove_user includes pre-backup)
        removed_data = await self.db.remove_user(user_id)

        if removed_data:
            # Unpack data based on schema
            uid, join_iso, create_iso, uname, scan_iso, pokes, invalid, unverified, scans = removed_data
            logger.info(f"Removed data for departing user {uid} ({uname}) ({reason})")

            # 2. Post Embed to Leavers Channel
            if self.leavers_channel:
                 status = "Invalid" if invalid else ("Unverified" if unverified else "Verified")
                 join_dt = datetime.fromisoformat(join_iso) if join_iso else None
                 create_dt = datetime.fromisoformat(create_iso) if create_iso else None
                 scan_dt = datetime.fromisoformat(scan_iso) if scan_iso else None

                 join_ts = f"<t:{int(join_dt.timestamp())}:f> (<t:{int(join_dt.timestamp())}:R>)" if join_dt else "Unknown"
                 create_ts = f"<t:{int(create_dt.timestamp())}:f> (<t:{int(create_dt.timestamp())}:R>)" if create_dt else "Unknown"
                 scan_ts = f"<t:{int(scan_dt.timestamp())}:f> (<t:{int(scan_dt.timestamp())}:R>)" if scan_dt else "Never"

                 embed = Embed(title="📤 Member Left", color=discord.Color.dark_grey(), timestamp=datetime.now(timezone.utc))
                 display_name = f"`{uname}`"
                 if member_object:
                     embed.set_thumbnail(url=member_object.display_avatar.url)
                     display_name = f"{member_object.mention} ({display_name})"

                 embed.add_field(name="User", value=display_name, inline=False)
                 embed.add_field(name="Last Known Status", value=f"`{status}`", inline=True)
                 embed.add_field(name="Pokes Received", value=f"`{pokes}`", inline=True)
                 embed.add_field(name="Times Scanned", value=f"`{scans}`", inline=True)
                 embed.add_field(name="Joined Server", value=join_ts, inline=False)
                 embed.add_field(name="Account Created", value=create_ts, inline=False)
                 embed.add_field(name="Last Scan Update", value=scan_ts, inline=False)
                 embed.set_footer(text=f"User ID: {uid} | Reason: {reason}")

                 await self._log_embed_to_channel(self.leavers_channel, embed, "User Leave")
            else:
                logger.warning(f"Leavers channel not configured, skipping embed for user {user_id}.")

            # 3. Log Success to Main Log Channel
            await self._log_to_channel(self.log_channel, f"✅ Successfully processed user leave for {uid} ({uname}). Reason: {reason}.", level=logging.INFO)

        else:
            # User wasn't in DB
            logger.info(f"User {user_id} left, but was not found in the tracking database.")
            await self._log_to_channel(self.log_channel, f"ℹ️ User {user_id} ({(member_object.name if member_object else 'Unknown Name')}) left, but was not tracked in the database.", level=logging.INFO)


    @commands.Cog.listener()
    async def on_message(self, message: Message):
        """Handle incoming messages for DMs and DM replies."""
        if message.author.bot:
            return # Ignore bots

        # --- DM Forwarding ---
        if message.guild is None: # Process DMs
            logger.info(f"Received DM from {message.author} ({message.author.id}).")

            if self.dm_forward_channel:
                user_db_info = await self.db.get_user(message.author.id)
                status_info = ""
                if user_db_info:
                     # Indices: 6=invalid_flag, 7=unverified_flag
                     invalid, unverified = user_db_info[6], user_db_info[7]
                     status = "Invalid" if invalid else ("Unverified" if unverified else "Verified")
                     status_info = f" (Tracked Status: `{status}`)"

                embed = Embed(description=message.content or "*(No text content)*", timestamp=message.created_at, color=discord.Color.blue())
                embed.set_author(name=f"DM from {message.author}{status_info}", icon_url=message.author.display_avatar.url)
                # Store context needed for reply in footer
                embed.set_footer(text=f"UserID={message.author.id}|OriginalMsgID={message.id}")

                attach_list = []
                if message.attachments:
                    for att in message.attachments:
                        attach_list.append(f"[{att.filename}]({att.url}) (Size: {att.size // 1024} KB)")
                if attach_list:
                    embed.add_field(name="Attachments", value="\n".join(attach_list)[:1024], inline=False)

                await self._log_embed_to_channel(self.dm_forward_channel, embed, "DM Forward")
                logger.info(f"Forwarded DM from {message.author.id} to #{self.dm_forward_channel.name}")
            else:
                logger.warning("DM Forward channel not configured, cannot forward DM.")

        # --- DM Reply Handling ---
        elif message.guild and self.dm_forward_channel and message.channel.id == self.dm_forward_channel.id and message.reference:
            # Check if it's a reply to one of *our* forwarded DM messages in the specific channel
            try:
                ref_message = await message.channel.fetch_message(message.reference.message_id)

                # Check if the referenced message was sent by the bot and has the expected footer
                if ref_message.author.id == self.user.id and ref_message.embeds:
                    footer_text = ref_message.embeds[0].footer.text
                    if footer_text and footer_text.startswith("UserID=") and "|OriginalMsgID=" in footer_text:
                        logger.debug(f"Detected reply by {message.author} in DM forward channel to bot message.")

                        # Check if the replier has permission
                        if not await self._check_command_permission(message.author):
                            logger.debug(f"User {message.author} lacks permission to reply via DM forward channel.")
                            try: await message.add_reaction("🚫") # Indicate lack of permission
                            except: pass
                            return # Ignore reply if user doesn't have roles

                        # Extract original user ID
                        try:
                            parts = footer_text.split('|')
                            user_id_part = parts[0].split('=')[1]
                            original_user_id = int(user_id_part)
                        except (IndexError, ValueError, TypeError) as e:
                            logger.error(f"Failed to parse UserID from footer '{footer_text}': {e}")
                            try: await message.add_reaction("❓") # Indicate parsing error
                            except: pass
                            return

                        # Get the original user
                        original_user = self.get_user(original_user_id) or await self.fetch_user(original_user_id)

                        if not original_user:
                            logger.warning(f"Could not find original user {original_user_id} to send reply.")
                            try: await message.add_reaction("❓") # Indicate user not found
                            except: pass
                            return

                        # Send the reply content as a DM
                        reply_content = message.content
                        if not reply_content and message.attachments:
                            reply_content = f"*(Staff sent attachment(s) in reply: {', '.join(a.filename for a in message.attachments)})*"
                        elif not reply_content:
                             reply_content = "*(Staff sent an empty reply)*"

                        reply_prefix = self.config['messages']['staff_reply_prefix']
                        full_dm_content = f"{reply_prefix}{reply_content}"

                        try:
                            await original_user.send(full_dm_content[:2000]) # Send DM (limit length)
                            logger.info(f"Successfully sent reply from {message.author} to {original_user} ({original_user_id}).")
                            await self._log_to_channel(self.log_channel, f"✉️ Staff Reply Sent: `{message.author}` replied to `{original_user}` (ID: {original_user_id}).", level=logging.INFO)
                            try: await message.add_reaction("✅") # Indicate success
                            except: pass
                        except discord.Forbidden:
                            logger.warning(f"Failed to send reply DM to {original_user} ({original_user_id}): DMs disabled or blocked.")
                            await self._log_to_channel(self.log_channel, f"⚠️ Staff Reply Failed: Cannot DM `{original_user}` (ID: {original_user_id}) - DMs likely disabled.", level=logging.WARNING)
                            try: await message.add_reaction("❌") # Indicate failure
                            except: pass
                        except discord.HTTPException as e:
                            logger.error(f"Failed to send reply DM to {original_user} ({original_user_id}): {e}")
                            await self._log_to_channel(self.log_channel, f"🚨 Staff Reply Failed: Discord API error sending DM to `{original_user}` (ID: {original_user_id}): {e}", level=logging.ERROR)
                            try: await message.add_reaction("❌") # Indicate failure
                            except: pass

            except discord.NotFound:
                # The referenced message was deleted, ignore.
                pass
            except discord.HTTPException as e:
                 logger.warning(f"HTTP error fetching referenced message ({message.reference.message_id}) for DM reply check: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during DM reply processing: {e}", exc_info=True)

        # Allow processing traditional commands here if we ever add any
        # await self.process_commands(message)


    # --- Helper Methods ---
    async def _log_to_channel(self, channel: Optional[TextChannel], message: str, level: int = logging.INFO):
        """Helper to send plain text logs to a specific channel."""
        log_prefix = {logging.INFO: "ℹ️", logging.WARNING: "⚠️", logging.ERROR: "🚨", logging.CRITICAL: "💥"}.get(level, "")
        full_message = f"{log_prefix} {message}"
        logger.log(level, f"Discord Log: {message}") # Log normally too
        if channel:
            try:
                # Split message if too long
                for chunk in [full_message[i:i+1990] for i in range(0, len(full_message), 1990)]:
                     await channel.send(chunk)
            except discord.Forbidden:
                logger.error(f"Missing permissions to send message in channel #{channel.name} ({channel.id}).")
            except Exception as e:
                logger.error(f"Failed to send message to channel #{channel.name}: {e}")

    async def _log_embed_to_channel(self, channel: Optional[TextChannel], embed: Embed, log_type: str):
        """Helper to send embed logs to a specific channel."""
        logger.info(f"Discord Log Embed ({log_type}) triggered.")
        if channel:
            try:
                await channel.send(embed=embed)
            except discord.Forbidden:
                logger.error(f"Missing permissions to send embed in channel #{channel.name} ({channel.id}).")
            except Exception as e:
                logger.error(f"Failed to send embed to channel #{channel.name}: {e}")

    async def _check_command_permission(self, user: Union[Member, User]) -> bool:
        """Checks if a user has either the general or developer role."""
        # NOTE: Potential for consolidation with the decorator checks
        if not isinstance(user, Member): return False # Cannot check roles for User object outside guild context

        dev_role_id = self.config['roles'].get('developer_role_id')
        gen_role_id = self.config['roles'].get('general_command_role_id')

        # Dev role always has permission
        if dev_role_id:
            dev_role = user.guild.get_role(dev_role_id)
            if dev_role and dev_role in user.roles:
                return True

        # General role check
        if gen_role_id:
            gen_role = user.guild.get_role(gen_role_id)
            if gen_role and gen_role in user.roles:
                return True
        elif not gen_role_id and not dev_role_id: # If NEITHER role is set, let's deny.
            logger.warning("Permission check: Neither developer nor general command role is configured.")
            return False

        return False # User has neither role

    # --- Permission Checks (Decorators) ---
    # NOTE: The logic here is similar to _check_command_permission. Could be consolidated.
    def is_general_user():
        async def predicate(interaction: Interaction) -> bool:
            bot: GatekeeperBot = interaction.client # type: ignore
            if not isinstance(interaction.user, Member): return False # Need member context for roles

            # Allow developer role to use general commands too
            if DevCommands.is_developer_check(interaction): return True

            role_id = bot.config['roles'].get('general_command_role_id')
            if not role_id: # If not set, only developers (checked above) can use general commands
                 logger.warning("general_command_role_id not set, restricting general commands to developers.")
                 # Send ephemeral message if interaction not already responded to
                 if not interaction.response.is_done():
                     await interaction.response.send_message("Command usage restricted: General command role not configured.", ephemeral=True)
                 return False

            if not interaction.guild: return False # Should have guild context
            role = interaction.guild.get_role(role_id)
            if not role:
                logger.warning(f"General command role {role_id} not found.")
                if not interaction.response.is_done():
                    await interaction.response.send_message("Required role for this command not found on server.", ephemeral=True)
                return False

            if role in interaction.user.roles:
                return True

            if not interaction.response.is_done():
                 await interaction.response.send_message("You do not have the required role to use this command.", ephemeral=True)
            return False
        return app_commands.check(predicate)

    def is_developer():
        async def predicate(interaction: Interaction) -> bool:
            if DevCommands.is_developer_check(interaction): return True
            # Send ephemeral message if interaction not already responded to
            if not interaction.response.is_done():
                await interaction.response.send_message("You must have the Developer role to use this command.", ephemeral=True)
            return False
        return app_commands.check(predicate)

# --- UI Elements ---
class ConfirmView(discord.ui.View):
    # Seems fine
    def __init__(self, authorized_user_id: int, timeout: float = 60.0):
        super().__init__(timeout=timeout)
        self.authorized_user_id = authorized_user_id
        self.confirmed: Optional[bool] = None
        self.message: Optional[Union[InteractionMessage, Message]] = None # Can be Interaction or regular Message

    async def interaction_check(self, interaction: Interaction) -> bool:
        if interaction.user.id != self.authorized_user_id:
            await interaction.response.send_message("You cannot interact with this confirmation.", ephemeral=True)
            return False
        return True

    async def _end_interaction(self, interaction: Interaction, confirmed: bool, message_text: str):
        self.confirmed = confirmed
        for item in self.children:
            if isinstance(item, discord.ui.Button): item.disabled = True
        try:
             # Check if it's an interaction response or a regular message edit
             if isinstance(self.message, InteractionMessage):
                 if interaction.response.is_done():
                     await interaction.edit_original_response(content=message_text, view=self)
                 else: # Should ideally not happen if message exists, but handle response edit
                     await interaction.response.edit_message(content=message_text, view=self)
             elif isinstance(self.message, Message): # Handle editing a regular message
                  await self.message.edit(content=message_text, view=self)
             else: # Fallback if message type unknown or None
                  await interaction.response.edit_message(content=message_text, view=self)

        except discord.NotFound: logger.warning("ConfirmView message not found on edit.")
        except discord.HTTPException as e: logger.error(f"Error editing ConfirmView message: {e}")
        except Exception as e: logger.error(f"Unexpected error editing ConfirmView message: {e}")
        self.stop()

    @discord.ui.button(label="Confirm", style=discord.ButtonStyle.danger, custom_id="confirm_yes")
    async def confirm_button(self, interaction: Interaction, button: discord.ui.Button):
        await self._end_interaction(interaction, True, "✅ Confirmed. Proceeding...")

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, custom_id="confirm_no")
    async def cancel_button(self, interaction: Interaction, button: discord.ui.Button):
        await self._end_interaction(interaction, False, "❌ Operation cancelled.")

    async def on_timeout(self):
        self.confirmed = None # Indicate timeout explicitly vs False (cancel)
        if self.message:
            for item in self.children:
                 if isinstance(item, discord.ui.Button): item.disabled = True
            try:
                 # Check if it's an interaction response or a regular message edit
                 if isinstance(self.message, InteractionMessage):
                     await self.message.edit(content="⏰ Confirmation timed out.", view=self)
                 elif isinstance(self.message, Message):
                      await self.message.edit(content="⏰ Confirmation timed out.", view=self)
            except discord.NotFound: pass
            except Exception as e: logger.error(f"Error editing ConfirmView on timeout: {e}")
        self.stop()


class PaginatorView(discord.ui.View):
    def __init__(self, embeds: List[Embed], interaction: Interaction, ephemeral: bool = False):
        super().__init__(timeout=300.0) # 5 minutes timeout
        self.embeds = embeds
        self.original_interaction = interaction # Store original interaction
        self.authorized_user_id = interaction.user.id # Store user ID for check
        self.ephemeral = ephemeral
        self.current_page = 0
        self.total_pages = len(embeds)
        self.message: Optional[InteractionMessage] = None
        self._update_buttons()

    async def send_initial_message(self):
        """Sends the first page via followup."""
        if not self.embeds:
             self.message = await self.original_interaction.followup.send("No content to display.", ephemeral=self.ephemeral)
             self.stop()
             return
        # Ensure message is stored correctly after sending
        self.message = await self.original_interaction.followup.send(embed=self.embeds[0], view=self, ephemeral=self.ephemeral)


    def _update_buttons(self):
        children = self.children
        # Ensure buttons exist by accessing them via custom_id
        prev_button = discord.utils.get(children, custom_id="paginator_prev")
        counter_button = discord.utils.get(children, custom_id="paginator_counter")
        next_button = discord.utils.get(children, custom_id="paginator_next")

        if prev_button and isinstance(prev_button, discord.ui.Button):
            prev_button.disabled = self.current_page == 0
        if counter_button and isinstance(counter_button, discord.ui.Button):
             counter_button.label = f"Page {self.current_page + 1}/{self.total_pages}"
        if next_button and isinstance(next_button, discord.ui.Button):
             next_button.disabled = self.current_page >= self.total_pages - 1

    async def show_page(self, interaction: Interaction, page_number: int):
        if not self.message or not self.embeds: return
        self.current_page = max(0, min(page_number, self.total_pages - 1))
        self._update_buttons()
        try:
            # Use interaction response for edits
            await interaction.response.edit_message(embed=self.embeds[self.current_page], view=self)
        except discord.NotFound:
             logger.warning("Paginator message not found on page change.")
             self.stop()
        except discord.HTTPException as e:
             logger.error(f"Error editing paginator message: {e}")
             # Maybe try to inform user ephemerally if edit fails? We don't have to error out here, but we can for now.
             # await interaction.followup.send("Error updating paginator.", ephemeral=True)


    @discord.ui.button(label="Previous", style=ButtonStyle.secondary, emoji="⬅️", custom_id="paginator_prev")
    async def previous_button(self, interaction: Interaction, button: discord.ui.Button):
        await self.show_page(interaction, self.current_page - 1)

    @discord.ui.button(label="Page x/y", style=ButtonStyle.secondary, disabled=True, custom_id="paginator_counter")
    async def page_counter(self, interaction: Interaction, button: discord.ui.Button):
        pass # Disabled button acts as label

    @discord.ui.button(label="Next", style=ButtonStyle.secondary, emoji="➡️", custom_id="paginator_next")
    async def next_button(self, interaction: Interaction, button: discord.ui.Button):
        await self.show_page(interaction, self.current_page + 1)

    async def interaction_check(self, interaction: Interaction) -> bool:
         # Only allow the original command user to interact
         if interaction.user.id != self.authorized_user_id:
              await interaction.response.send_message("You cannot interact with this paginator.", ephemeral=True)
              return False
         return True

    async def on_timeout(self):
         if self.message:
             for item in self.children:
                 if isinstance(item, discord.ui.Button): item.disabled = True
             try:
                 # Use edit on the message object directly
                 await self.message.edit(view=self)
             except discord.NotFound: pass
             except Exception as e: logger.error(f"Error disabling paginator buttons on timeout: {e}")
         self.stop()


# --- Command Groups ---

# ModCommands and AdminCommands are essentially the same thing now, I thought it made more sense this way
class AdminCommands(Group):
    """General commands for user verification management."""
    def __init__(self, bot: GatekeeperBot):
        super().__init__(name="gatekeeper", description="Manage user verification status")
        self.bot = bot

    # --- /gatekeeper scanlurkers --- (Spec 2.1)
    @app_commands.command(name="scanlurkers", description="Manually scan server members and update tracking.")
    @GatekeeperBot.is_general_user()
    @app_commands.checks.dynamic_cooldown(
        lambda i: app_commands.Cooldown(1, float(i.client.config['timers']['scan_cooldown_hours']) * 3600),
        key=lambda i: i.guild_id # type: ignore
    )
    async def scanlurkers(self, interaction: Interaction):
        """Command to manually trigger a member scan."""
        # PUBLIC command
        bot_instance: GatekeeperBot = self.bot
        try:
            # Defer publicly
            await interaction.response.defer(thinking=True, ephemeral=False)
            # perform_scan now handles sending followup messages based on interaction presence
            await bot_instance.perform_scan(invoked_by=f"Command ({interaction.user})", interaction=interaction)
            # Response (success/fail/progress) is handled within perform_scan
        except RuntimeError as e: # Catch scan-in-progress or backup failure
             # Send public followup for error
             if not interaction.response.is_done(): await interaction.response.send_message(f"⚠️ Scan aborted: {e}", ephemeral=False)
             else: await interaction.followup.send(f"⚠️ Scan aborted: {e}", ephemeral=False)
        except Exception as e:
            logger.error(f"Error during /gatekeeper scanlurkers command: {e}", exc_info=True)
            err_msg = f"❌ An unexpected error occurred during the scan: {e}"
            await bot_instance._log_to_channel(bot_instance.log_channel, f"🚨 Manual Scan Error ({interaction.user}): {e}", level=logging.ERROR)
            # Send public followup for error
            if not interaction.response.is_done(): await interaction.response.send_message(err_msg, ephemeral=False)
            else: await interaction.followup.send(err_msg, ephemeral=False)

    @scanlurkers.error # type: ignore
    async def scanlurkers_error(self, interaction: Interaction, error: app_commands.AppCommandError):
         """Handles errors specifically for scanlurkers, like cooldown."""
         bot_instance: GatekeeperBot = self.bot # type: ignore
         if isinstance(error, app_commands.CommandOnCooldown):
              retry_after_td = timedelta(seconds=error.retry_after)
              # Format timedelta nicely (e.g., "1 hour 5 minutes", "30 seconds")
              if retry_after_td.total_seconds() < 60:
                   retry_str = f"{error.retry_after:.1f} seconds"
              else:
                   mm, ss = divmod(retry_after_td.total_seconds(), 60)
                   hh, mm = divmod(mm, 60)
                   retry_str = ""
                   if hh > 0: retry_str += f"{int(hh)} hour{'s' if hh > 1 else ''} "
                   if mm > 0: retry_str += f"{int(mm)} minute{'s' if mm > 1 else ''} "
                   # retry_str += f"{int(ss)} second{'s' if ss > 1 else ''}" # Maybe too much detail
                   if not retry_str: retry_str = f"{error.retry_after:.1f} seconds" # Fallback

              # Send PUBLIC cooldown message
              await interaction.response.send_message(f"⏳ This command is on cooldown. Try again in {retry_str.strip()}.", ephemeral=False)
         elif isinstance(error, app_commands.CheckFailure):
             # Permission errors are handled ephemerally by the check itself, so don't send public message
             logger.debug(f"CheckFailure handled by decorator for {interaction.user} on /scanlurkers.")
             # Ensure interaction is acknowledged if check failed before deferral
             if not interaction.response.is_done():
                 # Send an ephemeral placeholder because the check already sent one
                 await interaction.response.send_message("Permission check failed.", ephemeral=True, delete_after=1)

         else:
              logger.error(f"Unhandled error in /gatekeeper scanlurkers: {error}", exc_info=True)
              msg = "An unexpected error occurred processing this command."
              # Send PUBLIC error message
              if not interaction.response.is_done(): await interaction.response.send_message(msg, ephemeral=False)
              else: await interaction.followup.send(msg, ephemeral=False)
              await bot_instance._log_to_channel(bot_instance.log_channel, f"🚨 Unhandled error in /scanlurkers: {error}", level=logging.ERROR)

    # --- /gatekeeper list --- (Spec 2.2)
    @app_commands.command(name="list", description="List users marked as invalid or unverified with full details.")
    @GatekeeperBot.is_general_user()
    @app_commands.describe(status="Which group of users to list")
    @app_commands.choices(status=[
        Choice(name="Invalid", value="invalid_account_flag"),
        Choice(name="Unverified", value="unverified_account_flag")
    ])
    async def list_users(self, interaction: Interaction, status: Choice[str]):
        """Lists users based on flag, showing all DB info, ordered by join date."""
        # PUBLIC command
        await interaction.response.defer(ephemeral=False, thinking=True) # Defer publicly
        bot_instance: GatekeeperBot = self.bot
        flag_name = status.value
        status_name = status.name # "Invalid" or "Unverified"

        try:
            # Sort by join_date ASC (earliest first)
            users_data = await bot_instance.db.get_users_by_flag(flag_name=flag_name, sort_by='join_date', order='ASC')

            if not users_data:
                await interaction.followup.send(f"✅ No users currently marked as `{status_name}`.", ephemeral=False)
                return

            items_per_page = 5 # Reduced items per page due to more data
            embeds = []
            total_users = len(users_data)

            for i, user_row in enumerate(users_data):
                 # Unpack ALL columns based on schema:
                 # user_id, join_date, account_creation_date, username,
                 # scan_issued_timestamp, poke_count, invalid_account_flag,
                 # unverified_account_flag, scan_update_count
                 (user_id, join_iso, create_iso, username, scan_iso,
                  pokes, invalid, unverified, scans) = user_row

                 member = interaction.guild.get_member(user_id) if interaction.guild else None
                 mention = member.mention if member else f"`{username}`"

                 # Format timestamps
                 join_dt = datetime.fromisoformat(join_iso) if join_iso else None
                 create_dt = datetime.fromisoformat(create_iso) if create_iso else None
                 scan_dt = datetime.fromisoformat(scan_iso) if scan_iso else None

                 join_ts = f"<t:{int(join_dt.timestamp())}:R>" if join_dt else "Unknown"
                 create_ts = f"<t:{int(create_dt.timestamp())}:R>" if create_dt else "Unknown"
                 scan_ts = f"<t:{int(scan_dt.timestamp())}:R>" if scan_dt else "Never"

                 # Build description string for this user
                 user_lines = [
                     f"**{mention} (`{user_id}`)**",
                     f"• **Username:** `{username}`",
                     f"• **Joined:** {join_ts} ({join_dt.strftime('%Y-%m-%d %H:%M') if join_dt else '?'})",
                     f"• **Created:** {create_ts} ({create_dt.strftime('%Y-%m-%d %H:%M') if create_dt else '?'})",
                     f"• **Pokes:** `{pokes}`",
                     f"• **Scans:** `{scans}`",
                     f"• **Last Scan:** {scan_ts}",
                     #f"• **Flags:** Inv=`{invalid}`, Unv=`{unverified}`" # Maybe too verbose
                 ]
                 user_info_block = "\n".join(user_lines)

                 # Add to current page or create new page
                 if i % items_per_page == 0:
                     # Start new embed page
                     page_num = (i // items_per_page) + 1
                     total_pages = (total_users + items_per_page - 1) // items_per_page
                     embed = Embed(title=f"📜 {status_name} User List (Page {page_num}/{total_pages})",
                                   color=discord.Color.red() if status_name == "Invalid" else discord.Color.orange())
                     embed.description = user_info_block # Start description
                     embed.set_footer(text=f"Total {status_name}: {total_users} | Sorted by Join Date (Oldest First)")
                     embeds.append(embed)
                 else:
                     # Append to current page's description
                     embeds[-1].description += f"\n\n{user_info_block}"
                     # Truncate if description gets too long (4096 limit)
                     if len(embeds[-1].description) > 4000:
                         embeds[-1].description = embeds[-1].description[:4000] + "\n... (truncated)"


            if embeds:
                 # Send PUBLIC paginator
                 view = PaginatorView(embeds, interaction, ephemeral=False)
                 await view.send_initial_message()
            else:
                 # Should be caught by the initial check, but as a fallback:
                 await interaction.followup.send(f"No `{status_name}` users found.", ephemeral=False)

        except Exception as e:
            logger.error(f"Error during /gatekeeper list command: {e}", exc_info=True)
            await interaction.followup.send(f"❌ An unexpected error occurred while listing users: {e}", ephemeral=False) # Public error
            await bot_instance._log_to_channel(bot_instance.log_channel, f"🚨 Error in /list command: {e}", level=logging.ERROR)


    # --- /gatekeeper poke --- (Spec 2.3)
    @app_commands.command(name="poke", description="Remind unverified users to verify.")
    @GatekeeperBot.is_general_user()
    @app_commands.describe(method="How to remind the users")
    @app_commands.choices(method=[
        Choice(name="Ping in Gate Channel", value="gate"),
        Choice(name="Send Direct Message (DM)", value="dm"),
        Choice(name="Both Gate Ping and DM", value="all")
    ])
    async def poke(self, interaction: Interaction, method: Choice[str]):
        """Sends reminders via specified method, increments poke count once per user."""
        # PUBLIC command
        await interaction.response.defer(thinking=True, ephemeral=False) # Defer publicly
        bot_instance: GatekeeperBot = self.bot
        method_val = method.value

        if not bot_instance.guild:
             await interaction.followup.send("Error: Guild context unavailable.", ephemeral=False); return

        # Get target users (unverified)
        try:
            unverified_users_data = await bot_instance.db.get_users_by_flag('unverified_account_flag', sort_by='join_date', order='ASC')
        except Exception as e:
             logger.error(f"Poke: Failed to fetch unverified users: {e}")
             await interaction.followup.send("❌ Failed to fetch unverified users from database.", ephemeral=False)
             return

        if not unverified_users_data:
            await interaction.followup.send("✅ No users currently marked as 'unverified' to poke.", ephemeral=False)
            return

        gate_channel = bot_instance.gate_channel
        dm_template = bot_instance.config['messages']['poke_dm_message']
        gate_template = bot_instance.config['messages']['poke_gate_message']

        if method_val in ['gate', 'all'] and not gate_channel:
            await interaction.followup.send("⚠️ Warning: Gatekeeper channel not configured or accessible. Cannot send channel pings.", ephemeral=False) # Public warning
            if method_val == 'gate': return # Abort if only gate was requested

        dm_success, dm_failed, gate_pings_sent, users_poked_ids = 0, 0, 0, set()
        rate_limit_delay = 1.1 # Seconds between DMs / Pings

        # --- Gate Ping Logic ---
        if method_val in ['gate', 'all'] and gate_channel:
            user_list_for_embed = []
            mentions_list = []
            ping_batch_size = 20 # Ping users in batches to avoid huge messages
            total_unverified = len(unverified_users_data)

            for i, user_row in enumerate(unverified_users_data):
                user_id, join_iso, _, username, *_ = user_row
                member = bot_instance.guild.get_member(user_id)
                if member:
                    join_dt = datetime.fromisoformat(join_iso) if join_iso else None
                    join_ts = f"<t:{int(join_dt.timestamp())}:R>" if join_dt else "Unknown"
                    user_list_for_embed.append(f"• {member.mention} (`{username}`) - Joined: {join_ts}")
                    mentions_list.append(member.mention)
                    users_poked_ids.add(user_id) # Add to set for DB update later

                    # Send batch if full or last user
                    if len(mentions_list) >= ping_batch_size or i == total_unverified - 1:
                        if not mentions_list: continue # Skip if batch empty (can happen on last iteration)
                        try:
                             ping_msg = gate_template.format(user_mentions=", ".join(mentions_list))
                             # Ensure message isn't too long
                             if len(ping_msg) > 1950: ping_msg = ping_msg[:1950] + "... (list truncated)"
                             await gate_channel.send(ping_msg, allowed_mentions=AllowedMentions(users=True))
                             gate_pings_sent += len(mentions_list)
                             logger.info(f"Sent gate ping batch for {len(mentions_list)} users.")
                             mentions_list = [] # Reset batch
                             await asyncio.sleep(rate_limit_delay) # Sleep between batches
                        except discord.HTTPException as e:
                             logger.error(f"Poke: HTTP error sending gate ping batch: {e}")
                             await bot_instance._log_to_channel(bot_instance.log_channel, f"🚨 Poke Gate Error: {e}", level=logging.ERROR)
                             # Maybe stop gate pings if one fails at some point. Let's log and continue for now.
                        except Exception as e:
                             logger.error(f"Poke: Unexpected error sending gate ping batch: {e}", exc_info=True)
                             await bot_instance._log_to_channel(bot_instance.log_channel, f"🚨 Poke Gate Error: {e}", level=logging.ERROR)

            # Create paginated embed for gate channel (Spec 2.3.1) - Send PUBLICLY to command channel
            if user_list_for_embed:
                 embeds = []
                 items_per_page = 15
                 for i in range(0, len(user_list_for_embed), items_per_page):
                     page_content = user_list_for_embed[i:i+items_per_page]
                     page_num = (i // items_per_page) + 1
                     total_pages = (len(user_list_for_embed) + items_per_page - 1) // items_per_page
                     embed = Embed(title=f"Unverified Users Poked in Gate (Oldest First) - Page {page_num}/{total_pages}",
                                   description="\n".join(page_content),
                                   color=discord.Color.orange())
                     embed.set_footer(text=f"Total Unverified Poked in Gate: {gate_pings_sent}")
                     embeds.append(embed)

                 if embeds:
                      # Send paginator PUBLICLY
                      paginator_view = PaginatorView(embeds, interaction, ephemeral=False)
                      # Use the view's send method which handles followup
                      await paginator_view.send_initial_message()


        # --- DM Logic ---
        if method_val in ['dm', 'all']:
            logger.info(f"Starting DM poke process for {len(unverified_users_data)} users...")
            for user_row in unverified_users_data:
                user_id = user_row[0]
                member = bot_instance.guild.get_member(user_id)
                if member:
                    try:
                        dm_content = dm_template.format(user_mention=member.mention, user_username=str(member))
                        await member.send(dm_content)
                        dm_success += 1
                        users_poked_ids.add(user_id) # Add to set for DB update
                        logger.debug(f"Sent poke DM to {member} ({user_id})")
                        await asyncio.sleep(rate_limit_delay) # Rate limit DMs
                    except discord.Forbidden:
                        dm_failed += 1
                        logger.warning(f"Poke DM failed to {user_id}: DMs disabled or blocked.")
                    except discord.HTTPException as e:
                        dm_failed += 1
                        logger.error(f"Poke DM HTTP error for {user_id}: {e}")
                        if e.status == 429: # Rate limited
                             retry_after = e.retry_after or 60.0 # Use retry_after if available, else 60s
                             logger.warning(f"Rate limited sending DMs. Pausing for {retry_after:.2f}s...")
                             await asyncio.sleep(retry_after)
                             await asyncio.sleep(rate_limit_delay) # Extra buffer
                             # Uhh maybe we rety the failed DM here? Figure it out later.
                        # For now, just count as failed
                    except Exception as e:
                        dm_failed += 1
                        logger.error(f"Poke DM unexpected error for {user_id}: {e}", exc_info=True)
                else:
                    logger.warning(f"Poke DM skipped for user {user_id}: Member not found in guild.")

        # --- Update Poke Count in DB ---
        if users_poked_ids:
            try:
                updated_count = await bot_instance.db.increment_poke_count(list(users_poked_ids))
                logger.info(f"Incremented poke count for {updated_count} users.")
            except Exception as e:
                logger.error(f"Poke: Failed to update poke counts in DB: {e}")
                await bot_instance._log_to_channel(bot_instance.log_channel, f"🚨 Poke DB Error: Failed to increment poke counts: {e}", level=logging.ERROR)


        # --- Report Summary ---
        summary_embed = Embed(title=f"📢 Poke Command Summary ({method.name})", color=discord.Color.blue())
        summary_lines = [f"Targeted Unverified Users: {len(unverified_users_data)}"]
        if method_val in ['gate', 'all']: summary_lines.append(f"Gate Channel Pings Sent: {gate_pings_sent}")
        if method_val in ['dm', 'all']: summary_lines.append(f"DM Success / Failed: {dm_success} / {dm_failed}")
        summary_lines.append(f"Total Unique Users Poked (DB updated): {len(users_poked_ids)}")

        summary_embed.description = "\n".join(summary_lines)
        # Send summary to Log channel
        await bot_instance._log_embed_to_channel(bot_instance.log_channel, summary_embed, "Poke Summary Log")
        # Also send PUBLIC confirmation to user who ran command
        # Check if we already sent the paginator followup for gate pings
        poke_followup_message = await interaction.original_response()
        if poke_followup_message and len(poke_followup_message.embeds) > 0 and "Unverified Users Poked in Gate" in poke_followup_message.embeds[0].title:
             # Already sent paginator, let's send another.
             await interaction.followup.send(embed=summary_embed, ephemeral=False)
        else:
            # If no paginator was sent, edit the original deferral message
             await interaction.edit_original_response(embed=summary_embed, view=None) # Remove indicator


# --- Developer Command Group ---
class DevCommands(Group):
    """Developer-only commands for bot management."""
    def __init__(self, bot: GatekeeperBot):
        super().__init__(name="dev", description="Developer-only commands")
        self.bot = bot

    @staticmethod
    def is_developer_check(interaction: Interaction) -> bool:
        """Standalone check logic for developer role."""
        # NOTE: Potential for consolidation with other permission checks
        bot: GatekeeperBot = interaction.client # type: ignore
        dev_role_id = bot.config['roles'].get('developer_role_id')
        if not dev_role_id: return False # No dev role configured
        if not interaction.guild or not isinstance(interaction.user, Member): return False # Need guild member context
        dev_role = interaction.guild.get_role(dev_role_id)
        if not dev_role: return False # Dev role not found on server
        if dev_role in interaction.user.roles:
            return True
        return False

    # --- /dev reload --- (Spec 2.4)
    @app_commands.command(name="reload", description="[Dev Only] Safely prepare for bot reload (Requires external restart).")
    @GatekeeperBot.is_developer()
    async def reload(self, interaction: Interaction):
        """Saves state, backs up, logs, and shuts down for external restart."""
        # EPHEMERAL command
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot_instance: GatekeeperBot = self.bot
        logger.warning(f"Reload requested by {interaction.user}. Preparing for shutdown...")

        log_msgs = [f"Reload initiated by {interaction.user}."]

        # 1. Save Data (Not much active state here, mainly DB)
        # If we add active timers or complex states, save them here
        log_msgs.append("Checked active states (minimal state held).")

        # 2. Backup DB
        backup_path = await bot_instance.db.backup(reason="pre_reload")
        if backup_path: log_msgs.append(f"Database backup created: `{os.path.basename(backup_path)}`")
        else: log_msgs.append("⚠️ Failed to create database backup before reload!")

        # 3. Validate/Audit (Optional, maybe just log config state)
        log_msgs.append("Logging current config state (excluding token).")
        safe_config = bot_instance.config.copy()
        if 'discord_token_env' in safe_config: safe_config['discord_token_env'] = '***' # Mask token var name too
        if 'discord_bot_token' in safe_config: del safe_config['discord_bot_token'] # Ensure token itself isn't logged
        try:
            config_str = yaml.dump(safe_config, indent=2, allow_unicode=True, sort_keys=False)
            log_msgs.append(f"```yaml\n{config_str[:1000]}\n```") # Log first part of config
        except Exception as dump_err:
            log_msgs.append(f"Could not dump config to string: {dump_err}")


        # 4. Provide Summary in Log Channel
        reload_embed = Embed(title="🔄 Bot Reload Sequence Initiated",
                             description="\n".join(log_msgs),
                             color=discord.Color.teal(),
                             timestamp=datetime.now(timezone.utc))
        await bot_instance._log_embed_to_channel(bot_instance.log_channel, reload_embed, "Reload Log")

        # 5. Confirm to user and Shutdown
        await interaction.followup.send("✅ Bot prepared for reload. Shutting down now. Ensure your process manager (like systemd or docker) restarts the bot.", ephemeral=True)
        # Add a small delay before closing to ensure message sends
        await asyncio.sleep(2)
        await bot_instance.close()

    # --- /dev config --- (Spec 2.5)
    @app_commands.command(name="config", description="[Dev Only] View or dynamically update config values (runtime only).")
    @GatekeeperBot.is_developer()
    @app_commands.describe(
        key="Config key path (e.g., 'timers.scan_interval_minutes' or 'roles.unverified_role_id')",
        value="New value (omit to view current value)"
    )
    async def config_cmd(self, interaction: Interaction, key: str, value: Optional[str] = None):
        """Dynamically views or updates config values. Does NOT save to file."""
        # EPHEMERAL command
        await interaction.response.defer(ephemeral=True)
        bot_instance: GatekeeperBot = self.bot
        keys = key.lower().split('.')
        target = bot_instance.config
        original_value_repr = "N/A"
        needs_restart = False # Flag if change requires restart

        try:
            # Traverse the config dict
            current_path = []
            for k in keys[:-1]:
                current_path.append(k)
                if isinstance(target, dict) and k in target:
                    target = target[k]
                else:
                    await interaction.followup.send(f"❌ Error: Invalid key path. Could not find `{k}` in `{' .'.join(current_path)}`.", ephemeral=True)
                    return

            last_key = keys[-1]
            if not isinstance(target, dict) or last_key not in target:
                await interaction.followup.send(f"❌ Error: Key `{last_key}` not found at path `{' .'.join(keys)}`.", ephemeral=True)
                return

            original_value = target.get(last_key) # Use get for safety
            original_value_repr = repr(original_value)

            # --- View Mode ---
            if value is None:
                # Mask sensitive keys if viewed directly
                if 'token' in last_key.lower() or 'key' in last_key.lower(): display_val = "***"
                else: display_val = repr(original_value)
                await interaction.followup.send(f"Current value for `{key}`: `{display_val}`", ephemeral=True)
                return

            # --- Update Mode ---
            new_value: Any = value
            # Use original_value's type if it's not None, otherwise guess based on key? Very risky. Let's require original value exists.
            if original_value is None and not isinstance(target.get(last_key), type(None)):
                 # Handle case where original value is explicitly None in config vs key not existing
                 original_type = type(None)
            elif original_value is not None:
                 original_type = type(original_value)
            else:
                 # Cannot determine original type if value is None and key existed but wasn't explicitly None?
                 # Let's default to string conversion in this edge case, but log a warning.
                 logger.warning(f"/dev config: Original value for '{key}' is None, attempting string conversion for update.")
                 original_type = str


            # Attempt type conversion and validation
            try:
                if original_type == bool:
                    new_value = value.lower() in ['true', '1', 'yes', 'on', 'y']
                elif original_type == int:
                    new_value = int(value)
                    # Basic validation for IDs/intervals
                    if ('id' in last_key and new_value <= 0) or ('interval' in last_key and new_value <= 0) or ('hours' in last_key and new_value <= 0) or ('count' in last_key and new_value < 0):
                         raise ValueError("Numeric value out of expected range (must be positive for IDs/timers).")
                elif original_type == float:
                    new_value = float(value)
                    if ('interval' in last_key and new_value <= 0) or ('hours' in last_key and new_value <= 0):
                         raise ValueError("Float value must be positive for timers.")
                elif original_type == list:
                     # Basic list support - assumes comma-separated input for now
                     # More complex list editing isn't really supported here
                     new_value = [item.strip() for item in value.split(',') if item.strip()]
                     # Try converting list items if original list had ints? For now, I wanna do this as strings.
                     logger.warning("List config update via command is basic, items stored as strings.")
                elif original_type == type(None):
                     # Let's try None if value is 'none'/'null'. Keep as strings is dodge
                     if value.lower() in ['none', 'null']: new_value = None
                     else: new_value = str(value) # Otherwise store as string
                else: # Default to string if type is unknown/complex
                     new_value = str(value)

            except (ValueError, TypeError) as e:
                 await interaction.followup.send(f"❌ Invalid value format for target type `{original_type.__name__}`: {e}", ephemeral=True)
                 return

            # Apply the change
            target[last_key] = new_value
            logger.warning(f"Runtime config '{key}' changed from {original_value_repr} to {repr(new_value)} by {interaction.user}.")

            # Check if change requires restart (e.g., changing core IDs, task intervals)
            # This is heuristic - better safe than sorry.
            if 'channel_id' in last_key or 'role_id' in last_key or 'interval' in last_key or 'hours' in last_key or 'path' in last_key or 'dir' in last_key or 'level' in last_key or 'log_file' in last_key:
                 needs_restart = True

            # Update relevant bot attributes if possible (e.g., channel objects)
            # Be careful here, direct modification can be risky
            if 'channel_id' in last_key:
                 # Recache all channels as we don't know which one changed easily
                 bot_instance.log_channel = bot_instance._get_channel_safe(bot_instance.config['channels'].get('log_channel_id'), 'Log')
                 bot_instance.dm_forward_channel = bot_instance._get_channel_safe(bot_instance.config['channels'].get('dm_forward_channel_id'), 'DM Forward')
                 bot_instance.gate_channel = bot_instance._get_channel_safe(bot_instance.config['channels'].get('gate_channel_id'), 'Gate')
                 bot_instance.leavers_channel = bot_instance._get_channel_safe(bot_instance.config['channels'].get('leavers_channel_id'), 'Leavers')
                 logger.info("Channel objects re-cached after config change.")
            # Restart background tasks if timers changed? Too complex/risky. Recommend restart.

            restart_msg = "\n**Note:** A bot restart (`/dev reload`) is recommended for this change to fully take effect, especially for background tasks or core IDs." if needs_restart else ""
            await interaction.followup.send(f"✅ Updated runtime config `{key}` to `{repr(new_value)}`.\n(Original: `{original_value_repr}`){restart_msg}\n\n**This change is temporary.** Use `/dev saveconfig` to make it permanent.", ephemeral=True)

        except Exception as e:
            logger.error(f"Error processing /dev config command: {e}", exc_info=True)
            await interaction.followup.send(f"❌ An unexpected error occurred: {e}", ephemeral=True)

    # --- /dev saveconfig ---
    @app_commands.command(name="saveconfig", description="[Dev Only] Saves current runtime configuration to config.yaml.")
    @GatekeeperBot.is_developer()
    async def saveconfig(self, interaction: Interaction):
        """Saves the current runtime config back to the file."""
        # EPHEMERAL command
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot_instance: GatekeeperBot = self.bot

        view = ConfirmView(interaction.user.id)
        # Use followup for the confirmation message
        confirm_message = await interaction.followup.send(f"⚠️ **WARNING:** Overwrite `{CONFIG_FILE}` with the current runtime configuration?\nThis action is permanent.", view=view, ephemeral=True)
        view.message = confirm_message # Assign message for timeout editing
        await view.wait()

        if view.confirmed:
            try:
                # Backup current file first
                backup_config_path = f"{CONFIG_FILE}.bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(CONFIG_FILE, backup_config_path)
                logger.info(f"Backed up current config to {backup_config_path}")

                # Prepare config for saving (remove sensitive/runtime-only data if needed)
                save_config = bot_instance.config.copy()
                # Ensure token env var name is saved, but not the token itself if it somehow got loaded
                if 'discord_bot_token' in save_config: del save_config['discord_bot_token']

                # Write to file using safe_dump for potentially complex structures
                with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                    yaml.safe_dump(save_config, f, default_flow_style=False, indent=2, sort_keys=False, allow_unicode=True)

                logger.warning(f"Runtime config saved to {CONFIG_FILE} by {interaction.user}.")
                await interaction.edit_original_response(content=f"✅ Runtime config successfully saved to `{CONFIG_FILE}`.\nPrevious version backed up to `{os.path.basename(backup_config_path)}`.", view=None)
            except Exception as e:
                logger.error(f"Failed to save configuration: {e}", exc_info=True)
                await interaction.edit_original_response(content=f"❌ Failed to save configuration: {e}", view=None)
                await bot_instance._log_to_channel(bot_instance.log_channel, f"🚨 Failed to save config: {e}", level=logging.ERROR)
        else: # Cancelled or timed out
             # Edit based on confirmation status (False = Cancel, None = Timeout)
             result_msg = "❌ Config save cancelled." if view.confirmed is False else "⏰ Config save timed out."
             await interaction.edit_original_response(content=result_msg, view=None)

    # --- /dev healthcheck --- (Spec 2.6)
    @app_commands.command(name="healthcheck", description="[Dev Only] Validate integrity of the current or a backup database.")
    @GatekeeperBot.is_developer()
    @app_commands.describe(filename="Optional: Backup filename in backup dir (e.g., backup_xyz.db)")
    async def healthcheck(self, interaction: Interaction, filename: Optional[str] = None):
        """Performs DB integrity check and posts result to Log channel."""
        # EPHEMERAL command
        await interaction.response.defer(ephemeral=True)
        bot_instance: GatekeeperBot = self.bot
        target_db_path = None
        target_name = "current database"

        if filename:
            # Sanitize filename slightly
            safe_filename = os.path.basename(filename) # Prevent path traversal
            target_db_path = os.path.join(bot_instance.db.backup_dir, safe_filename)
            target_name = f"backup file '{safe_filename}'"
            if not os.path.exists(target_db_path):
                 await interaction.followup.send(f"❌ Error: Backup file not found: `{target_db_path}`", ephemeral=True)
                 return

        # Perform check
        db_ok, result_msg = await bot_instance.db.health_check(db_filepath=target_db_path)

        # Create embed
        embed = Embed(title=f"🩺 Database Health Check ({target_name})",
                      description=result_msg,
                      color=discord.Color.green() if db_ok else discord.Color.red(),
                      timestamp=datetime.now(timezone.utc))
        embed.set_footer(text=f"Check requested by {interaction.user}")

        # Log to Log Channel
        await bot_instance._log_embed_to_channel(bot_instance.log_channel, embed, "DB Health Check")
        # Confirm to user
        await interaction.followup.send(f"✅ Health check performed for {target_name}. Results logged to Log channel.", ephemeral=True)


    # --- /dev restore --- (Spec 2.7)
    @app_commands.command(name="restore", description="[Dev Only] Restore database from backup (REQUIRES RESTART).")
    @GatekeeperBot.is_developer()
    @app_commands.describe(filename="Backup filename within the backup directory.")
    async def restore(self, interaction: Interaction, filename: str):
        """Restores DB from backup, logs process, requires restart."""
        # EPHEMERAL command
        await interaction.response.defer(ephemeral=True, thinking=True)
        bot_instance: GatekeeperBot = self.bot
        # Sanitize filename
        safe_filename = os.path.basename(filename)
        target_backup_path = os.path.join(bot_instance.db.backup_dir, safe_filename)

        if not os.path.exists(target_backup_path):
             await interaction.followup.send(f"❌ Error: Backup file not found: `{target_backup_path}`", ephemeral=True); return

        # Confirmation
        view = ConfirmView(interaction.user.id, timeout=120.0)
        confirm_message = await interaction.followup.send(f"⚠️ **WARNING:** Restore database from `{safe_filename}`?\n"
                                                       f"This **overwrites** the current live database (`{os.path.basename(bot_instance.db.db_path)}`) "
                                                       f"and **requires a manual bot restart** afterwards.",
                                                       view=view, ephemeral=True)
        view.message = confirm_message
        await view.wait()

        if view.confirmed:
            log_msgs = [f"Restore initiated by {interaction.user} from `{safe_filename}`."]
            logger.warning(f"DB restore initiated by {interaction.user} from {safe_filename}")

            # Restore function already handles pre-restore backup
            success = await bot_instance.db.restore(safe_filename) # Pass only filename

            if success:
                log_msgs.append(f"✅ Database successfully restored from `{safe_filename}`.")
                log_msgs.append(f"🔴 **BOT MUST BE RESTARTED MANUALLY NOW.**")
                result_msg = f"✅ DB restored from `{safe_filename}`.\n🔴 **RESTART BOT NOW**."
                log_color = discord.Color.green()
            else:
                log_msgs.append(f"❌ Database restore failed. Check logs for details.")
                log_msgs.append(f"ℹ️ The database might be in an inconsistent state or rolled back to pre-restore backup.")
                result_msg = "❌ DB restore failed. Check logs."
                log_color = discord.Color.red()

            # Log detailed summary to Log Channel
            restore_embed = Embed(title="🛠️ Database Restore Attempt",
                                  description="\n".join(log_msgs),
                                  color=log_color,
                                  timestamp=datetime.now(timezone.utc))
            await bot_instance._log_embed_to_channel(bot_instance.log_channel, restore_embed, "DB Restore Log")
            # Update user interaction
            await interaction.edit_original_response(content=result_msg, view=None)

        else: # Cancelled or timed out
             result_msg = "❌ DB restore cancelled." if view.confirmed is False else "⏰ DB restore timed out."
             await interaction.edit_original_response(content=result_msg, view=None)

    # --- /dev backup --- (Added for convenience, matching previous code)
    @app_commands.command(name="backup", description="[Dev Only] Manually trigger an immediate database backup.")
    @GatekeeperBot.is_developer()
    async def backup_cmd(self, interaction: Interaction):
        """Manually triggers a database backup."""
        # EPHEMERAL command
        await interaction.response.defer(ephemeral=True)
        bot_instance: GatekeeperBot = self.bot
        backup_path = await bot_instance.db.backup(reason="manual_trigger")
        if backup_path:
            msg = f"✅ Manual DB backup created: `{os.path.basename(backup_path)}`"
            await bot_instance._log_to_channel(bot_instance.log_channel, f"ℹ️ {msg} (Triggered by {interaction.user})", level=logging.INFO)
        else:
            msg = "❌ Manual DB backup failed. Check logs."
            await bot_instance._log_to_channel(bot_instance.log_channel, f"🚨 {msg} (Triggered by {interaction.user})", level=logging.ERROR)
        await interaction.followup.send(msg, ephemeral=True)

# --- Help Command (Top Level) --- (Spec 2.8)
# Needs to be defined outside class to be registered easily at top level
@app_commands.command(name="help", description="Shows available Gatekeeper commands.")
async def help_command(interaction: Interaction):
    """Displays help information based on user roles."""
    # PUBLIC command
    bot_instance: GatekeeperBot = interaction.client # type: ignore
    is_dev = DevCommands.is_developer_check(interaction)

    # Directly check if the user has the general role or if the role isn't set (allowing all)
    # Also allow devs to see general commands.
    has_general_role = False
    general_role_id = bot_instance.config['roles'].get('general_command_role_id')
    # If general role not set, only devs can use general commands (is_dev check covers this)
    allow_all_general = False # Explicitly false, rely on role check or dev check

    if interaction.guild and isinstance(interaction.user, Member):
        if general_role_id:
            general_role = interaction.guild.get_role(general_role_id)
            if general_role and general_role in interaction.user.roles:
                has_general_role = True
        # else: if no general role ID is set, has_general_role remains False

    show_general_cmds = is_dev or has_general_role


    embed = Embed(title=f"🛡️ {bot_instance.user.name} Help",
                  description=f"Commands for managing user verification.\n{bot_instance.config['messages']['embed_header']}",
                  color=discord.Color.purple())

    # Always show help
    embed.add_field(name="/help", value="Shows this help message.", inline=False)

    # Use the corrected check result
    if show_general_cmds:
         embed.add_field(name="--- General Commands ---", value="*(Usable by Staff/Devs)*", inline=False)
         embed.add_field(name="/gatekeeper scanlurkers", value="Manually scans members and updates tracking database.", inline=False)
         embed.add_field(name="/gatekeeper list `status:[Invalid|Unverified]`", value="Lists users by status with full details.", inline=False)
         embed.add_field(name="/gatekeeper poke `method:[Gate|DM|All]`", value="Sends reminders to unverified users.", inline=False)

    if is_dev:
        embed.add_field(name="--- Developer Commands ---", value="*(Usable by Devs Only)*", inline=False)
        embed.add_field(name="/dev reload", value="Safely prepares bot for external restart.", inline=False)
        embed.add_field(name="/dev config `key` `[value]`", value="Views or temporarily modifies runtime config.", inline=False)
        embed.add_field(name="/dev saveconfig", value="Saves current runtime config to `config.yaml`.", inline=False)
        embed.add_field(name="/dev healthcheck `[filename]`", value="Checks integrity of current or backup DB.", inline=False)
        embed.add_field(name="/dev restore `filename`", value="Restores DB from backup (Requires Restart!).", inline=False)
        embed.add_field(name="/dev backup", value="Manually triggers an immediate DB backup.", inline=False)


    embed.set_footer(text=f"{bot_instance.config['messages']['embed_footer']} | Use commands by typing '/'")
    # Send PUBLIC help message
    await interaction.response.send_message(embed=embed, ephemeral=False)


# --- Main Function and Bot Startup ---
def main():
    # Load configuration first to get logger settings and token env var name
    global config # Make config accessible globally if needed (e.g., for task intervals)
    try:
        config = load_config()
    except Exception as e:
         # Error already printed in load_config, just exit
         print(f"CRITICAL: Failed to load configuration. Exiting. Error: {e}", file=sys.stderr)
         sys.exit(1)

    # Setup logging using loaded config
    global logger # Make logger global
    logger = setup_logging(config)

    # Load environment variables (after getting var name from config)
    load_dotenv()
    token_env_var = config.get('discord_token_env')
    BOT_TOKEN = os.getenv(token_env_var) if token_env_var else None
    if not BOT_TOKEN:
        logger.critical(f"CRITICAL ERROR: Discord bot token environment variable '{token_env_var}' not found or not set.")
        sys.exit(1)

    # Initialize Database Manager
    db_manager = DatabaseManager(config['database']['path'], config['database']['backup_dir'])

    # Initialize Bot
    bot = GatekeeperBot(config=config, db_manager=db_manager)

    # --- Start the Bot ---
    try:
        logger.info("Starting bot...")
        # Pass None for handler to prevent discord.py from setting up its own root logger handler
        # Setup logging before running
        bot.run(BOT_TOKEN, log_handler=None, log_level=logging.WARNING) # Set discord lib level higher here
    except discord.LoginFailure:
        logger.critical("Failed to log in: Invalid Discord token.")
    except discord.PrivilegedIntentsRequired:
         logger.critical("Failed to start: Required Privileged Intents (Server Members, Message Content) are not enabled in the Discord Developer Portal.")
    except Exception as e:
        logger.critical(f"Critical error during bot execution: {e}", exc_info=True)
    finally:
        # Cleanup tasks
        logger.info("Bot process attempting graceful shutdown...")
        # Ensure DB connection is closed if loop ends unexpectedly
        # Running async code here is tricky after the loop might have stopped
        try:
             # Try to run the close async function if loop exists
             loop = asyncio.get_running_loop()
             if loop.is_running():
                 # Schedule closure and wait briefly
                 loop.create_task(db_manager.close())
                 # asyncio.run(asyncio.sleep(1)) # Allow loop iteration for closure task? Risky.
             else:
                 # If loop stopped, run synchronously (might block briefly)
                 asyncio.run(db_manager.close())
        except RuntimeError as e: # Catch cases where event loop is closed
             logger.warning(f"Could not run async DB close (loop likely closed): {e}")
             # Try a final synchronous attempt if possible? Very difficult state.
        except Exception as close_err:
            logger.error(f"Error during final DB close: {close_err}")
        logger.info("Bot process terminated.")

if __name__ == "__main__":
    main()