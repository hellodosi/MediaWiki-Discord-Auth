# MediaWiki Discord Authentication Extension

Eine MediaWiki-Erweiterung zur Authentifizierung über Discord OAuth2 mit Server- und Rollenzugehörigkeitsprüfung.

## Anforderungen

- MediaWiki 1.35+
- PHP 8.2+
- Discord Application mit OAuth2

## Installation

1. Laden Sie die Erweiterung in das Verzeichnis `extensions/DiscordAuth` herunter
2. Fügen Sie folgende Zeile zu Ihrer `LocalSettings.php` hinzu:

```php
wfLoadExtension( 'DiscordAuth' );
```

## Discord Application einrichten

1. Gehen Sie zu [Discord Developer Portal](https://discord.com/developers/applications)
2. Erstellen Sie eine neue Application oder wählen Sie eine bestehende aus
3. Navigieren Sie zu **OAuth2** → **General**
4. Notieren Sie sich die **Client ID** und **Client Secret**
5. Fügen Sie unter **Redirects** folgende URL hinzu:
   ```
   https://ihr-wiki.example.com/index.php/Special:Login
   ```
6. Unter **OAuth2** → **URL Generator** wählen Sie die Scopes:
   - `identify`
   - `guilds.members.read`

## Konfiguration

Fügen Sie folgende Konfiguration zu Ihrer `LocalSettings.php` hinzu:

```php
// Discord OAuth2 Credentials
$wgDiscordClientId = 'IHRE_CLIENT_ID';
$wgDiscordClientSecret = 'IHR_CLIENT_SECRET';

// Discord Server (Guild) ID
$wgDiscordGuildId = 'IHRE_SERVER_ID';

// Erlaubte Rollen (Role IDs) - optional
// Wenn leer, ist nur Server-Mitgliedschaft erforderlich
$wgDiscordAllowedRoles = [
    '123456789012345678',  // Beispiel Role ID
    '987654321098765432',  // Weitere Role ID
];

// Automatische Benutzererstellung aktivieren
$wgDiscordAutoCreate = true;

// Authentifizierungsmodus (siehe unten für Details)
$wgDiscordAuthMode = 'optional';  // 'optional', 'required', oder 'supplement'

// Discord Role zu MediaWiki-Gruppen Zuordnung (optional)
// WICHTIG: Verwenden Sie das Array-of-Objects Format für Discord Snowflake IDs
$wgDiscordRoleToGroupMapping = [
    ['role' => '123456789012345678', 'group' => 'sysop'],                        // Eine Rolle → eine Gruppe
    ['role' => '987654321098765432', 'group' => ['bureaucrat', 'editor']],       // Eine Rolle → mehrere Gruppen
    ['role' => '111222333444555666', 'group' => 'autoconfirmed'],                // Weitere Rolle → eine Gruppe
];

// Gruppen-Synchronisations-Modus (optional, Standard: 'always')
$wgDiscordGroupSyncMode = 'always';  // 'always', 'once', oder 'disabled'
```

### Authentifizierungsmodi

Die Extension unterstützt drei verschiedene Modi:

#### 1. **'optional'** (Standard) - Beides möglich
```php
$wgDiscordAuthMode = 'optional';
```
- ✅ Benutzer können sich mit Discord **oder** Passwort anmelden
- ✅ Benutzer können Passwörter setzen/ändern
- ✅ Bestehende Benutzer können Discord nachträglich verknüpfen
- **Ideal für:** Bestehende Wikis, die Discord als zusätzliche Option anbieten

#### 2. **'required'** (Empfohlen für neue Wikis) - Nur Discord
```php
$wgDiscordAuthMode = 'required';
```
- ✅ **Nur Discord-Login möglich**
- ❌ Passwort-Felder werden ausgeblendet
- ❌ Benutzer können keine Passwörter setzen/ändern
- ✅ Automatische Benutzererstellung bei Discord-Login
- **Ideal für:** Neue, geschlossene Wikis nur für Discord-Community

#### 3. **'supplement'** - Passwort erforderlich
```php
$wgDiscordAuthMode = 'supplement';
```
- ✅ Benutzer **müssen** ein Passwort haben
- ✅ Discord-Login als zusätzliche Bequemlichkeit
- ✅ Passwort als Fallback wenn Discord-Zugang verloren
- **Ideal für:** Wikis mit höheren Sicherheitsanforderungen

### Discord IDs finden

**Server ID (Guild ID):**
1. Aktivieren Sie den Entwicklermodus in Discord (Benutzereinstellungen → Erweitert → Entwicklermodus)
2. Rechtsklick auf Ihren Server → **Server-ID kopieren**

**Rollen ID (Role ID):**
1. Servereinstellungen → Rollen
2. Rechtsklick auf eine Rolle → **Rolle-ID kopieren**

## Verwendung

### Für neue Benutzer

1. Gehen Sie zur Login-Seite Ihres Wikis
2. Klicken Sie auf **"Mit Discord anmelden"**
3. Autorisieren Sie die Application im Discord OAuth2-Fenster
4. **Wählen Sie Ihren Benutzernamen** (der Discord-Username wird vorgeschlagen)
5. Sie werden automatisch eingeloggt, wenn:
   - Sie Mitglied des konfigurierten Discord-Servers sind
   - Sie eine der erlaubten Rollen haben (falls konfiguriert)

### Für bestehende Benutzer (Discord-Konto verknüpfen)

Bestehende Wiki-Benutzer können ihr Discord-Konto nachträglich verknüpfen:

1. **Melden Sie sich normal** in Ihrem Wiki-Konto an
2. Gehen Sie zu: `Special:LinkDiscord` oder `Spezial:Discord-Konto_verknüpfen`
3. Klicken Sie auf **"Discord-Konto verknüpfen"**
4. Autorisieren Sie die Application im Discord OAuth2-Fenster
5. Ihr Discord-Konto ist nun mit Ihrem Wiki-Konto verknüpft

Ab jetzt können Sie sich mit Discord anmelden, auch wenn Sie ursprünglich mit Passwort registriert haben.

**Verknüpfung aufheben:**
- Gehen Sie zu `Special:LinkDiscord`
- Klicken Sie auf **"Discord-Konto trennen"**

### Benutzername-Format

Neue Benutzer können ihren Benutzernamen frei wählen (ohne "Discord:" Präfix).
Die Verknüpfung erfolgt über die Discord-ID, nicht über den Benutzernamen.

## Automatische Gruppen-Synchronisation

### Discord Rollen → MediaWiki Gruppen

Die Extension kann automatisch MediaWiki-Benutzergruppen basierend auf Discord-Rollen zuweisen.

### Konfiguration

```php
// Discord Role zu MediaWiki-Gruppen Zuordnung
// WICHTIG: Discord Snowflake IDs sind sehr große Zahlen (18-19 Stellen).
// PHP/MediaWiki verliert diese IDs bei Verwendung als Array-Keys.
// Verwenden Sie daher das Array-of-Objects Format:
$wgDiscordRoleToGroupMapping = [
    ['role' => 'DISCORD_ROLE_ID', 'group' => 'mediawiki_group_name'],           // Eine Rolle → eine Gruppe
    ['role' => 'DISCORD_ROLE_ID', 'group' => ['group1', 'group2']],             // Eine Rolle → mehrere Gruppen

    ['role' => '123456789012345678', 'group' => 'sysop'],                       // Discord Admins → Wiki Admins
    ['role' => '987654321098765432', 'group' => ['bureaucrat', 'editor']],      // Discord Mods → Mehrere Gruppen
];

// Gruppen-Synchronisations-Modus
$wgDiscordGroupSyncMode = 'always';  // 'always', 'once', oder 'disabled'
```

**Discord Role ID finden:**
1. Discord Entwicklermodus aktivieren (Benutzereinstellungen → Erweitert)
2. Servereinstellungen → Rollen
3. Rechtsklick auf Rolle → **Rolle-ID kopieren**

### Synchronisations-Modi

#### 1. **'always'** (Standard) - Kontinuierliche Synchronisation
```php
$wgDiscordGroupSyncMode = 'always';
```
- ✅ **Bei Registrierung:** Gruppen werden automatisch zugewiesen
- ✅ **Bei jedem Login:** Gruppen werden automatisch synchronisiert
- ✅ **Beim Verknüpfen:** Gruppen werden beim Verknüpfen eines Discord-Kontos synchronisiert
- ✅ **Bidirektional:** Fehlende Gruppen werden hinzugefügt, überflüssige entfernt
- ✅ **Nur gemappte Gruppen:** Andere Gruppen bleiben unberührt
- **Ideal für:** Wikis wo Berechtigungen zentral über Discord verwaltet werden sollen

#### 2. **'once'** - Einmalige Synchronisation
```php
$wgDiscordGroupSyncMode = 'once';
```
- ✅ **Bei Registrierung:** Gruppen werden automatisch zugewiesen
- ✅ **Beim Verknüpfen:** Gruppen werden beim ersten Verknüpfen synchronisiert
- ❌ **Bei Logins:** Keine Synchronisation bei späteren Logins
- **Manuelle Verwaltung:** Gruppen können danach im Wiki manuell angepasst werden
- **Ideal für:** Wikis wo Discord nur für die initiale Rechtevergabe genutzt wird

#### 3. **'disabled'** - Keine automatische Synchronisation
```php
$wgDiscordGroupSyncMode = 'disabled';
```
- ❌ **Keine automatische Synchronisation**
- **Manuelle Verwaltung:** Alle Gruppen müssen über `Special:UserRights` verwaltet werden
- **Ideal für:** Wikis die Discord nur zur Authentifizierung nutzen

### Beispiel-Szenarien (mit 'always' Modus)

#### Szenario 1: Neue Registrierung
```
Discord-Nutzer hat Rollen: [Admin, VIP]
Konfiguration: ['role' => '123...456', 'group' => 'sysop']

Ergebnis: Wiki-Account wird mit Gruppe 'sysop' erstellt
```

#### Szenario 2: Bestehender Nutzer verliert Discord-Rolle
```
Vor Login: Wiki-Gruppen: [sysop, bureaucrat]
Discord-Rollen: [VIP] (Admin-Rolle verloren)
Nach Login: Wiki-Gruppen: [bureaucrat]

→ 'sysop' wurde automatisch entfernt
```

#### Szenario 3: Nutzer erhält neue Discord-Rolle
```
Vor Login: Wiki-Gruppen: [editor]
Discord-Rollen: [Editor, Moderator] (neu)
Konfiguration: ['role' => '789...012', 'group' => 'bureaucrat']
Nach Login: Wiki-Gruppen: [editor, bureaucrat]

→ 'bureaucrat' wurde automatisch hinzugefügt
```

#### Szenario 4: Eine Rolle → Mehrere Gruppen
```
Discord-Nutzer hat Rolle: [Admin]
Konfiguration: ['role' => '123...456', 'group' => ['sysop', 'bureaucrat', 'interface-admin']]

Ergebnis: Benutzer erhält alle drei Gruppen automatisch
```

### Admin-Übersicht: Gruppen-Synchronisation

**Special:DiscordMembershipCheck** zeigt für jeden Benutzer:

✅ **Synchronisiert:**
```
Gruppen: ✓ sysop, bureaucrat
```

⚠️ **Nicht synchronisiert:**
```
Gruppen: ⚠️ Gruppen-Konflikt
Erwartet: sysop, bureaucrat
Aktuell: editor, sysop
→ [Benutzerrechte verwalten]
```

**Link "Benutzerrechte verwalten":**
- Führt direkt zu `Special:UserRights` für den Benutzer
- Ermöglicht manuelle Anpassung der Gruppenzuordnung

### Wichtige Hinweise

⚠️ **Sicherheit:**
- Die Extension synchronisiert **nur gemappte Gruppen**
- Andere Gruppen (z.B. manuell vergebene) bleiben unberührt
- Admins können Gruppen weiterhin manuell über `Special:UserRights` verwalten

⚠️ **Performance:**
- Synchronisation erfolgt bei jedem Discord-Login (nur bei `'always'` Modus)
- Keine Hintergrund-Jobs erforderlich
- Live-Abfrage der Discord-Rollen via API

💡 **Empfehlung:**
- Verwenden Sie `'always'` wenn Discord die zentrale Berechtigungsquelle ist
- Verwenden Sie `'once'` wenn Sie nur initiale Gruppen zuweisen möchten
- Verwenden Sie `'disabled'` wenn Sie volle manuelle Kontrolle benötigen

💡 **Best Practice:**
```php
// Empfohlene Struktur:
$wgDiscordRoleToGroupMapping = [
    // Kritische Berechtigungen
    ['role' => 'ADMIN_ROLE_ID', 'group' => 'sysop'],
    ['role' => 'MOD_ROLE_ID', 'group' => 'bureaucrat'],

    // Spezielle Gruppen
    ['role' => 'EDITOR_ROLE_ID', 'group' => 'editor'],
    ['role' => 'TRUSTED_ROLE_ID', 'group' => 'autoconfirmed'],
];

// Hinweis: Gruppen müssen in MediaWiki existieren
// Custom Groups können über Extensions oder $wgGroupPermissions definiert werden
```

## Sicherheit

- Die Erweiterung verwendet State-Parameter für CSRF-Schutz
- Access Tokens werden nicht gespeichert
- OAuth2 Code Exchange erfolgt serverseitig

## Was passiert bei Verlust der Mitgliedschaft?

### Benutzer verlässt Discord-Server oder verliert Rolle

**Szenario:** Ein Benutzer ist im Wiki registriert, verlässt aber den Discord-Server oder verliert die erforderliche Rolle.

### Verhalten nach Authentifizierungsmodus:

#### Mit `$wgDiscordAuthMode = 'optional'` (Standard):

1. **Discord-Login:** ❌ Blockiert
   - Fehlermeldung: "Sie sind kein Mitglied des erforderlichen Discord-Servers"

2. **Passwort-Login:** ✅ Funktioniert weiterhin
   - Der Benutzer kann sich mit Benutzername/Passwort anmelden
   - Zugriff bleibt erhalten

**Geeignet für:** Wikis wo ehemalige Mitglieder Zugriff behalten sollen

---

#### Mit `$wgDiscordAuthMode = 'required'` (Discord-only):

1. **Discord-Login:** ❌ Blockiert
   - Fehlermeldung: "Sie sind kein Mitglied des erforderlichen Discord-Servers"

2. **Passwort-Login:** ❌ Nicht verfügbar
   - Benutzer können keine Passwörter setzen/ändern

**Ergebnis:** ⚠️ **Benutzer ist komplett ausgesperrt**

**Geeignet für:** Private Discord-Community-Wikis mit strenger Zugangskontrolle

**Wichtig:**
- ✅ Die Mitgliedschaftsprüfung erfolgt **bei jedem Discord-Login** live
- ✅ Keine zeitliche Verzögerung - sofortiger Effekt
- ⚠️ Admins sollten regelmäßig inaktive Accounts prüfen/löschen

---

#### Mit `$wgDiscordAuthMode = 'supplement'`:

1. **Discord-Login:** ❌ Blockiert
2. **Passwort-Login:** ✅ Funktioniert (Fallback)

**Geeignet für:** Wikis mit höheren Sicherheitsanforderungen

### Zusammenfassung

| Modus | Discord-Login | Passwort-Login | Zugriff verloren? |
|-------|---------------|----------------|-------------------|
| `optional` | ❌ | ✅ | **Nein** |
| `required` | ❌ | ❌ | **Ja** ✅ |
| `supplement` | ❌ | ✅ | **Nein** |

### Empfehlung für 'required' Modus:

Wenn Sie `required` verwenden, sollten Sie:
1. ✅ Benutzer vorab informieren über die Zugangsrichtlinien
2. ✅ Klare Regeln für Server-Mitgliedschaft kommunizieren
3. ⚠️ Admin-Account mit Maintenance-Script-Zugang behalten für Notfälle
4. ✅ **Admin-Tool verwenden:** `Special:DiscordMembershipCheck` (siehe unten)

## Admin-Tool: Mitgliedschaftsprüfung

### Special:DiscordMembershipCheck

Die Extension bietet eine Admin-SpecialPage zur Überprüfung aller Benutzer mit Discord-Verknüpfung.

**Features:**
- ✅ **Live-Prüfung** aller Benutzer mit Discord-Konto
- ✅ **Übersichtliche Statistiken** (Gültig / Ungültig / Gesperrt)
- ✅ **Sortierbare Tabellen** nach Status
- ✅ **Ein-Klick-Sperrung** für Benutzer ohne Zugang
- ✅ **Automatische Sperrgrund-Dokumentation**

**Zugriff:** Nur für Benutzer mit `block`-Berechtigung (i.d.R. Administratoren)

### Setup:

1. **Discord Bot erstellen:**
   - Gehen Sie zu https://discord.com/developers/applications
   - Erstellen Sie eine neue Application (oder nutzen Sie die bestehende)
   - Gehen Sie zu **Bot** → **Add Bot**
   - Aktivieren Sie unter **Privileged Gateway Intents**: **SERVER MEMBERS INTENT** ⚠️ Wichtig!
   - Kopieren Sie den Bot-Token

2. **Bot zum Server hinzufügen:**
   - Gehen Sie zu **OAuth2** → **URL Generator**
   - Wählen Sie Scope: `bot`
   - Wählen Sie Permissions: **Read Messages/View Channels**
   - Öffnen Sie die generierte URL und fügen Sie den Bot zu Ihrem Server hinzu

3. **Token konfigurieren:**
   ```php
   $wgDiscordBotToken = 'IHR_BOT_TOKEN_HIER';
   ```

4. **Tool nutzen:**
   - Gehen Sie zu `Special:DiscordMembershipCheck`
   - Klicken Sie auf "Benutzer sperren" für invalide Benutzer

### Beispiel-Screenshot (Funktion):

```
┌─────────────────────────────────────────────────────────┐
│ Discord-Mitgliedschaftsüberprüfung                      │
├─────────────────────────────────────────────────────────┤
│ Statistiken:                                            │
│  [12]  [10]   [2]   [0]                                │
│  Gesamt Gültig Ungültig Gesperrt                       │
├─────────────────────────────────────────────────────────┤
│ ⚠️  Benutzer ohne gültigen Zugang:                     │
│ ┌──────────┬───────────┬────────────┬─────────────┐   │
│ │ Wiki     │ Discord   │ Discord ID │ Aktion      │   │
│ ├──────────┼───────────┼────────────┼─────────────┤   │
│ │ MaxMust  │ max#1234  │ 123456789  │ [Sperren]   │   │
│ │ AltUser  │ old#5678  │ 987654321  │ [Sperren]   │   │
│ └──────────┴───────────┴────────────┴─────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Fehlermeldungen

Die Extension verwendet folgende i18n-Schlüssel für Fehlermeldungen:

- `discordauth-error-invalid-state` - Ungültiger State-Parameter
- `discordauth-error-token` - Token-Exchange fehlgeschlagen
- `discordauth-error-userinfo` - Benutzerinformationen konnten nicht abgerufen werden
- `discordauth-error-not-member` - Benutzer ist kein Mitglied des Servers
- `discordauth-error-no-role` - Benutzer hat keine der erforderlichen Rollen
- `discordauth-error-no-account` - Kein Wiki-Account vorhanden und AutoCreate deaktiviert

## Konfigurationsoptionen

| Option | Typ | Standard | Beschreibung |
|--------|-----|----------|--------------|
| `$wgDiscordClientId` | string | - | Discord Application Client ID (erforderlich) |
| `$wgDiscordClientSecret` | string | - | Discord Application Client Secret (erforderlich) |
| `$wgDiscordGuildId` | string | - | Discord Server ID (erforderlich) |
| `$wgDiscordAllowedRoles` | array | `[]` | Array von erlaubten Role IDs (optional, leer = nur Server-Mitgliedschaft) |
| `$wgDiscordAutoCreate` | bool | `false` | Automatische Benutzererstellung bei Discord-Login |
| `$wgDiscordAuthMode` | string | `'optional'` | Authentifizierungsmodus: `'optional'`, `'required'`, oder `'supplement'` |
| `$wgDiscordBotToken` | string | `''` | Discord Bot Token für Admin-Tools (optional, nur für Special:DiscordMembershipCheck) |
| `$wgDiscordRoleToGroupMapping` | array | `[]` | Zuordnung Discord Role ID → MediaWiki Gruppe (optional) |
| `$wgDiscordGroupSyncMode` | string | `'always'` | Gruppen-Synchronisations-Modus: `'always'` (bei jedem Login), `'once'` (nur bei Registrierung), `'disabled'` (keine Synchronisation) |

## Entwicklung

### Dateistruktur

```
extensions/DiscordAuth/
├── DiscordAuthenticationRequest.php
├── DiscordPrimaryAuthenticationProvider.php
├── extension.json
├── ConfigAndHttpRequestFactories.json
├── DiscordAuthConfig.json
├── DiscordAuthConfigSchema.json
├── DiscordAuthenticationErrors.json
├── DiscordAuthenticationMessages.json
├── DiscordConfigurationSettings.json
└── README.md
```

### PHP 8.2 Kompatibilität

Die Extension ist vollständig kompatibel mit PHP 8.2 und nutzt:
- Strikte Return-Types
- Nullable Return-Types (`?array`)
- Parameter Type Declarations

## Troubleshooting

**Problem: Login-Schleife**
- Überprüfen Sie, ob die Redirect URI in Discord korrekt konfiguriert ist
- Stellen Sie sicher, dass `$wgServer` in LocalSettings.php korrekt gesetzt ist

**Problem: "Not a member" Fehler**
- Überprüfen Sie die Guild ID
- Stellen Sie sicher, dass der Bot die richtigen Permissions hat
- Verifizieren Sie, dass der Benutzer tatsächlich Mitglied ist

**Problem: "No role" Fehler**
- Überprüfen Sie die Role IDs
- Testen Sie mit leerem `$wgDiscordAllowedRoles` Array
- Verifizieren Sie die Rollenzuweisungen im Discord-Server

## Support

Bei Problemen oder Fragen öffnen Sie bitte ein Issue im Repository.
