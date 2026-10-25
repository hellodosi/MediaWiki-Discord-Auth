# MediaWiki Discord Authentication Extension

> 🇩🇪 *Diese Dokumentation ist auch auf Deutsch verfügbar: [README.de.md](README.de.md)*

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/X8X01TGZLU)

A MediaWiki extension providing authentication via Discord OAuth2 with server and role membership verification, automatic group synchronization, and dedicated administration tools.

## Requirements

- MediaWiki 1.35+
- PHP 8.2+
- Discord Application with OAuth2

## Installation

1. Download or clone the extension into your `extensions/DiscordAuth` directory.
2. Add the following line to your `LocalSettings.php`:

```php
wfLoadExtension( 'DiscordAuth' );
```

3. Run the MediaWiki database update script (creates the `discordauth_links` table and automatically migrates any existing links):

```bash
php maintenance/update.php
```

> **Note:** If running `update.php` manually is not possible (e.g., in shared hosting environments without shell access), the extension will automatically attempt to create the `discordauth_links` table in the background and migrate legacy entries upon first request. However, executing `update.php` remains recommended.

## Setting up Discord Application

1. Open the [Discord Developer Portal](https://discord.com/developers/applications).
2. Create a new Application (or select an existing one).
3. Navigate to **OAuth2** → **General**.
4. Note down your **Client ID** and **Client Secret**.
5. Under **Redirects**, add your wiki's login callback URL:
   ```
   https://your-wiki.example.com/index.php/Special:Login
   ```
6. Under **OAuth2** → **URL Generator**, select the scopes:
   - `identify`
   - `guilds.members.read`

## Configuration

Add the configuration settings to your `LocalSettings.php`:

```php
// Discord OAuth2 Credentials
$wgDiscordClientId = 'YOUR_CLIENT_ID';
$wgDiscordClientSecret = 'YOUR_CLIENT_SECRET';

// Discord Server (Guild) ID
$wgDiscordGuildId = 'YOUR_SERVER_ID';

// Allowed Discord roles (Role IDs) - optional
// If left empty, server membership alone is sufficient
$wgDiscordAllowedRoles = [
    '123456789012345678',  // Example Role ID
    '987654321098765432',  // Another Role ID
];

// Enable automatic account creation on first login
$wgDiscordAutoCreate = true;

// Authentication mode ('optional', 'required', or 'supplement')
$wgDiscordAuthMode = 'optional';

// Discord Role to MediaWiki Group mapping (optional)
// IMPORTANT: Use the array-of-objects format for Discord snowflake IDs
$wgDiscordRoleToGroupMapping = [
    ['role' => '123456789012345678', 'group' => 'sysop'],                        // One role → one group
    ['role' => '987654321098765432', 'group' => ['bureaucrat', 'editor']],       // One role → multiple groups
    ['role' => '111222333444555666', 'group' => 'autoconfirmed'],                // Another role → one group
];

// Group synchronization mode (optional, default: 'always')
$wgDiscordGroupSyncMode = 'always';  // 'always', 'once', or 'disabled'
```

### Authentication Modes

The extension supports three authentication modes:

#### 1. **'optional'** (Default) - Both Discord and password allowed
```php
$wgDiscordAuthMode = 'optional';
```
- ✅ Users can log in using either Discord **or** standard password
- ✅ Users can set or change passwords
- ✅ Existing accounts can link their Discord profile at any time
- **Best for:** Established wikis offering Discord as an additional convenient login method

#### 2. **'required'** (Recommended for community wikis) - Discord only
```php
$wgDiscordAuthMode = 'required';
```
- ✅ **Discord login only**
- ❌ Password fields are hidden from login forms
- ❌ Users cannot set or change passwords
- ✅ Automatic account creation upon Discord login
- **Best for:** Private, closed wikis exclusive to a Discord community

#### 3. **'supplement'** - Password required, Discord optional
```php
$wgDiscordAuthMode = 'supplement';
```
- ✅ Users **must** have a password
- ✅ Discord login serves as an extra convenience
- ✅ Password acts as fallback if Discord access is lost
- **Best for:** Wikis with stricter multi-channel security policies

### Finding Discord IDs

**Server ID (Guild ID):**
1. Enable Developer Mode in Discord (*User Settings* → *Advanced* → *Developer Mode*).
2. Right-click your server icon → **Copy Server ID**.

**Role ID:**
1. Open *Server Settings* → *Roles*.
2. Right-click the desired role → **Copy Role ID**.

## Usage

### For New Users

1. Visit your wiki's login page.
2. Click **"Log in with Discord"**.
3. Authorize the application in the Discord OAuth2 dialog.
4. **Choose your wiki username** (the Discord username is suggested automatically).
5. You are logged in automatically if:
   - You are a member of the configured Discord server.
   - You possess one of the allowed roles (if configured).

### For Existing Users (Linking Accounts)

Existing wiki accounts can link their Discord profile afterwards:

1. **Log in normally** to your wiki account.
2. Navigate to `Special:LinkDiscord`.
3. Click **"Link Discord Account"**.
4. Authorize the application in the Discord OAuth2 dialog.
5. Your Discord account is now linked.

You can now log in via Discord at any time.

**Unlinking:**
- Visit `Special:LinkDiscord`.
- Click **"Disconnect Discord Account"**.

### Username Format

New users can freely choose their wiki username (without any mandatory `Discord:` prefix). The internal connection is maintained exclusively via the unique numeric Discord ID.

## Discord Profile Display & User Lists

The extension provides several ways to showcase and link verified Discord profiles throughout the wiki.

### 1. Automatic Sidebar Link (Toolbox)
When viewing the user page of a registered wiki user (`User:Name`) who has linked their Discord account, a direct profile link automatically appears in the sidebar (*Tools* / *Toolbox*):
* **Format:** `[Username] on Discord`
* **Target:** Opens the user's Discord profile (`https://discord.com/users/<Discord-ID>`) in a new tab.

### 2. Parser Functions (Wikitext)
Embed Discord links and IDs anywhere in wikitext or templates:

* **`{{#discordlink:Username|LinkText}}`**
  Renders a formatted external link to the user's Discord profile.
  * *Example:* `{{#discordlink:Dominik|Contact via Discord}}`
  * *Default behavior:* If the username is omitted, it defaults to the current user page. If link text is omitted, it defaults to "Discord-Profil".
* **`{{#discordid:Username}}`**
  Outputs the raw numeric Discord ID of the user.
  * *Example:* `{{#discordid:Dominik}}`

### 3. User Lists & Grids (`<userlist>`)
The `<userlist>` tag renders customizable user lists (card grid layout by default, or compact horizontal list):

* **Display users of a specific group (card grid):**
  ```html
  <userlist group="sysop" show="name,mail" displayname="real" />
  ```
* **Display specific users:**
  ```html
  <userlist users="User1,User2" show="name,mail,role" displayname="both" />
  ```
* **Compact list view:**
  ```html
  <userlist group="sysop" show="role" layout="list" />
  ```
* **Display all registered users:**
  ```html
  <userlist />
  <!-- Or explicitly: -->
  <userlist group="*" />
  ```
* **Exclude specific accounts:**
  ```html
  <userlist group="sysop" exclude="AdminBot,TestUser" />
  ```

#### Attributes:
* **`group`**: The MediaWiki user group (e.g. `sysop`, `bureaucrat`). If omitted or set to `*` / `all`, all registered users are shown.
* **`users`**: A comma-separated list of usernames (ignored if `group` is specified).
* **`exclude`**: Comma-separated list of usernames to exclude from the output.
* **`show`**: Fields to display from the user's infobox template.
* **`displayname`**: How the name is formatted (`real`, `wiki`, or `both`).
* **`layout`**: Layout style: `card` (default grid) or `list` (horizontal compact rows).
* **`fallbackimage`**: Default avatar image filename if none is present (default: `Person.jpg`).

## Automatic Group Synchronization

### Discord Roles → MediaWiki Groups

The extension automatically maps and synchronizes MediaWiki user groups based on Discord roles.

### Configuration

```php
// Discord Role to MediaWiki Group mapping
// IMPORTANT: Discord snowflake IDs are 64-bit integers (18-19 digits).
// Use the array-of-objects structure to avoid integer key truncation in PHP:
$wgDiscordRoleToGroupMapping = [
    ['role' => 'DISCORD_ROLE_ID', 'group' => 'mediawiki_group_name'],           // One role → one group
    ['role' => 'DISCORD_ROLE_ID', 'group' => ['group1', 'group2']],             // One role → multiple groups

    ['role' => '123456789012345678', 'group' => 'sysop'],                       // Discord Admins → Wiki Admins
    ['role' => '987654321098765432', 'group' => ['bureaucrat', 'editor']],      // Discord Mods → Multiple groups
];

// Synchronization mode
$wgDiscordGroupSyncMode = 'always';  // 'always', 'once', or 'disabled'
```

### Sync Modes

#### 1. **'always'** (Default) - Continuous Synchronization
```php
$wgDiscordGroupSyncMode = 'always';
```
- ✅ **On registration:** Groups are assigned automatically.
- ✅ **On every login:** Groups are synchronized with current Discord roles.
- ✅ **On account linking:** Groups sync when a user links their Discord account.
- ✅ **Bidirectional:** Adds newly qualified groups and removes revoked mapped groups.
- ✅ **Safe:** Unmapped groups (e.g. manually granted) remain untouched.

#### 2. **'once'** - Initial Synchronization Only
```php
$wgDiscordGroupSyncMode = 'once';
```
- ✅ Groups are synchronized only upon registration or initial account link.
- ❌ No synchronization on subsequent logins.
- Allows administrators to manage all rights inside the wiki manually afterwards.

#### 3. **'disabled'** - No Automatic Sync
```php
$wgDiscordGroupSyncMode = 'disabled';
```
- ❌ All group assignments must be managed manually via `Special:UserRights`.

## Security & Architecture

- **State Parameter:** Strict CSRF mitigation on OAuth2 authorization redirects.
- **No Stored Tokens:** Discord access tokens are exchanged server-side and never persisted in database records.
- **Dedicated Table:** Discord account associations are stored in the dedicated `discordauth_links` database table, completely decoupled from `user_properties` to guarantee links are never deleted by user preference updates or resets.

## What Happens When Membership Is Lost?

### Behavior by Authentication Mode:

#### With `$wgDiscordAuthMode = 'optional'` (Default):
1. **Discord Login:** ❌ Blocked (error: *"You are not a member of the required Discord server"*).
2. **Password Login:** ✅ Continues to work.

#### With `$wgDiscordAuthMode = 'required'` (Discord-Only):
1. **Discord Login:** ❌ Blocked.
2. **Password Login:** ❌ Disabled.
* **Result:** The user is completely locked out. Role and membership checks occur live on every Discord login without cache delays.

#### With `$wgDiscordAuthMode = 'supplement'`:
1. **Discord Login:** ❌ Blocked.
2. **Password Login:** ✅ Functions as fallback.

### Summary

| Mode | Discord Login | Password Login | Wiki Access Lost? |
|------|---------------|----------------|-------------------|
| `optional` | ❌ | ✅ | **No** |
| `required` | ❌ | ❌ | **Yes** ✅ |
| `supplement` | ❌ | ✅ | **No** |

## Administration Tools

The extension provides administrators (users with the `block` permission or sysop status) dedicated management tools:

### 1. Manual Account Linking (`Special:LinkDiscord`)
Administrators can manually link or unlink accounts at the bottom of `Special:LinkDiscord`:
* **Assign Discord ID:** Assigns a Discord ID to any registered wiki user. Snowflake format (15–22 digits) is strictly validated. A Discord ID cannot be accidentally linked to multiple accounts.
* **Remove Link:** Leaving the Discord ID blank requires checking an explicit confirmation checkbox to prevent accidental unlinking.

### 2. User Merge & Deletion (`Special:DiscordUserMerge`)
Allows administrators to merge or clean up user accounts:
* **Merge Accounts (Source & Target specified):**
  * All revisions, uploads, and log entries from the **source user** are reattributed to the **target user**.
  * The source user account and its Discord link are permanently removed.
  * The user page is redirected to the target user.
* **Pure Deletion (Source only):**
  * Revisions are anonymized and assigned to *"Gelöschter Benutzer"* (ID 0).
  * The account and its Discord link are removed from the database.

### 3. Membership & Role Audit (`Special:DiscordMembershipCheck`)
Audits all users with linked Discord accounts against the live Discord API:
* **Live status verification:** Checks server membership and configured roles in real time.
* **Group discrepancy warning:** Flags any mismatch between expected mapped groups and actual wiki groups.
* **One-click block action:** Quickly blocks accounts that left the Discord community.

**Setup Bot Token:**
1. Create a Bot in the [Discord Developer Portal](https://discord.com/developers/applications) and enable **SERVER MEMBERS INTENT** under *Privileged Gateway Intents*.
2. Add the bot to your server.
3. Configure the token in `LocalSettings.php`:
   ```php
   $wgDiscordBotToken = 'YOUR_BOT_TOKEN_HERE';
   ```

### 4. Database Storage & Migration
Account connections are stored in the dedicated table `discordauth_links`:
* **Protection against data loss:** Completely independent of MediaWiki's user options (`user_properties`). Saving or resetting preferences on `Special:Preferences` cannot touch Discord links.
* **Automatic Migration:** The included maintenance script `Maintenance/MigrateDiscordLinks.php` runs automatically via `update.php` to migrate legacy entries.

## Configuration Options Summary

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `$wgDiscordClientId` | string | `''` | Discord Application Client ID (required) |
| `$wgDiscordClientSecret` | string | `''` | Discord Application Client Secret (required) |
| `$wgDiscordGuildId` | string | `''` | Discord Server (Guild) ID (required) |
| `$wgDiscordAllowedRoles` | array | `[]` | Array of allowed Role IDs (optional, empty = server membership only) |
| `$wgDiscordAutoCreate` | bool | `false` | Automatically create accounts upon first Discord login |
| `$wgDiscordAuthMode` | string | `'optional'` | Auth mode: `'optional'`, `'required'`, or `'supplement'` |
| `$wgDiscordBotToken` | string | `''` | Discord Bot Token (optional, needed for `Special:DiscordMembershipCheck`) |
| `$wgDiscordRoleToGroupMapping` | array | `[]` | Mapping of Discord Role IDs to MediaWiki groups |
| `$wgDiscordGroupSyncMode` | string | `'always'` | Group sync mode: `'always'`, `'once'`, or `'disabled'` |
| `$wgDiscordSessionTimeout` | int | `604800` | Session timeout in seconds for Discord-authenticated users (1 week) |

## Development

### Directory Structure

```
extensions/DiscordAuth/
├── DiscordLinkStore.php                      # Storage layer managing discordauth_links
├── DiscordPrimaryAuthenticationProvider.php  # MediaWiki Primary Authentication Provider
├── DiscordAuthenticationRequest.php          # AuthManager authentication request class
├── Hooks.php                                 # MediaWiki hook subscribers
├── MembershipChecker.php                     # Role and membership verification logic
├── UserList.php                              # <userlist> tag and parser function renderers
├── SpecialDiscordLogin.php                   # OAuth callback, login & user onboarding
├── SpecialLinkDiscord.php                    # Account linking/unlinking (incl. admin panel)
├── SpecialDiscordMembershipCheck.php         # Real-time bot membership & role audit
├── SpecialDiscordUserMerge.php               # Account merging & deletion tool
├── SpecialDiscordDebug.php                   # Configuration and role mapping diagnostics
├── Maintenance/
│   └── MigrateDiscordLinks.php               # Maintenance script migrating legacy properties
├── sql/
│   ├── mysql/discordauth_links.sql           # Schema definition for MySQL / MariaDB
│   ├── sqlite/discordauth_links.sql          # Schema definition for SQLite
│   └── postgres/discordauth_links.sql        # Schema definition for PostgreSQL
├── i18n/
│   ├── de.json, en.json, be.json, es.json, fr.json, it.json, pl.json, pt.json, ru.json, qqq.json
├── extension.json                            # MediaWiki extension manifest
├── README.md                                 # English documentation
└── README.de.md                              # German documentation
```

### PHP 8.2 Compatibility

The extension is fully compatible with PHP 8.2+ and adheres to strict typing, nullable return types (`?array`, `?string`), and parameter declarations.

## Troubleshooting

* **Login redirect loop:** Verify that the Redirect URI in the Discord Developer Portal matches `$wgServer` exactly.
* **"Not a member" error:** Ensure `$wgDiscordGuildId` is correct and that the user has joined the server.
* **"No role" error:** Verify role IDs in `$wgDiscordAllowedRoles`. Test with an empty array to isolate role-specific issues.
* **Bot check fails:** Confirm that **SERVER MEMBERS INTENT** is activated in the Discord Developer Portal for your bot.

## Support

For questions, issues, or contributions, please open an issue in the GitHub repository.
