<?php

namespace DiscordAuth;

use MediaWiki\MediaWikiServices;
use MediaWiki\User\UserIdentity;
use Wikimedia\Rdbms\IConnectionProvider;

/**
 * Central storage for the link between wiki accounts and Discord accounts.
 *
 * The link used to be stored as user options ("discord_id" / "discord_username")
 * in the user_properties table. MediaWiki treats unregistered options as "unused"
 * and deletes them whenever a user saves Special:Preferences, which caused links
 * to disappear. The links are therefore stored in a dedicated table now.
 */
class DiscordLinkStore {

	public const TABLE = 'discordauth_links';

	/** @var IConnectionProvider */
	private $dbProvider;

	/** @var array<int,array|false> Per-request cache: user ID => link row or false */
	private $cache = [];

	/** @var bool Static flag so table existence is checked at most once per PHP request */
	private static $tableChecked = false;

	/** @var self|null */
	private static $instance = null;

	public function __construct( IConnectionProvider $dbProvider ) {
		$this->dbProvider = $dbProvider;
	}

	public static function getInstance(): self {
		if ( self::$instance === null ) {
			self::$instance = new self( MediaWikiServices::getInstance()->getConnectionProvider() );
		}
		return self::$instance;
	}

	/**
	 * Ensures that the discordauth_links table exists.
	 * If the administrator did not run maintenance/update.php, this will
	 * attempt to automatically create the table on-the-fly and migrate legacy data.
	 */
	public function ensureTable(): void {
		if ( self::$tableChecked ) {
			return;
		}

		try {
			$dbr = $this->dbProvider->getReplicaDatabase();
			if ( !$dbr->tableExists( self::TABLE, __METHOD__ ) ) {
				$dbw = $this->dbProvider->getPrimaryDatabase();
				$dbType = $dbw->getType();
				$sqlFile = __DIR__ . "/sql/$dbType/discordauth_links.sql";

				if ( file_exists( $sqlFile ) ) {
					$dbw->sourceFile( $sqlFile );
					wfDebugLog( 'DiscordAuth', '[DiscordLinkStore] Automatically created missing table ' . self::TABLE );
					$this->autoMigrateLegacyOptions( $dbw );
				}
			}
			self::$tableChecked = true;
		} catch ( \Throwable $e ) {
			wfDebugLog( 'DiscordAuth', '[DiscordLinkStore] ensureTable warning: ' . $e->getMessage() );
		}
	}

	/**
	 * Checks if the storage table is available.
	 */
	public function isAvailable(): bool {
		$this->ensureTable();
		try {
			return (bool)$this->dbProvider->getReplicaDatabase()->tableExists( self::TABLE, __METHOD__ );
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	/**
	 * Opportunistic automatic migration for legacy user_properties links.
	 *
	 * @param \Wikimedia\Rdbms\IDatabase $dbw
	 */
	private function autoMigrateLegacyOptions( $dbw ): void {
		try {
			$res = $dbw->newSelectQueryBuilder()
				->select( [ 'up_user', 'up_property', 'up_value' ] )
				->from( 'user_properties' )
				->where( [ 'up_property' => [ 'discord_id', 'discord_username' ] ] )
				->caller( __METHOD__ )
				->fetchResultSet();

			$legacy = [];
			foreach ( $res as $row ) {
				$legacy[(int)$row->up_user][$row->up_property] = trim( (string)$row->up_value );
			}

			$now = $dbw->timestamp();
			$cleanupUserIds = [];

			foreach ( $legacy as $userId => $props ) {
				$discordId = $props['discord_id'] ?? '';
				$discordUsername = $props['discord_username'] ?? '';
				if ( $discordId === '' ) {
					continue;
				}

				$exists = (bool)$dbw->newSelectQueryBuilder()
					->select( 'user_id' )
					->from( 'user' )
					->where( [ 'user_id' => $userId ] )
					->caller( __METHOD__ )
					->fetchField();
				if ( !$exists ) {
					continue;
				}

				$conflict = (bool)$dbw->newSelectQueryBuilder()
					->select( 'dal_user' )
					->from( self::TABLE )
					->where( [ 'dal_discord_id' => $discordId ] )
					->caller( __METHOD__ )
					->fetchField();
				if ( $conflict ) {
					continue;
				}

				$dbw->newInsertQueryBuilder()
					->insertInto( self::TABLE )
					->row( [
						'dal_user' => $userId,
						'dal_discord_id' => $discordId,
						'dal_discord_username' => $discordUsername,
						'dal_linked_at' => $now,
						'dal_updated_at' => $now,
					] )
					->caller( __METHOD__ )
					->execute();

				$cleanupUserIds[] = $userId;
			}

			if ( $cleanupUserIds ) {
				$dbw->newDeleteQueryBuilder()
					->deleteFrom( 'user_properties' )
					->where( [
						'up_user' => $cleanupUserIds,
						'up_property' => [ 'discord_id', 'discord_username' ],
					] )
					->caller( __METHOD__ )
					->execute();
			}
		} catch ( \Throwable $e ) {
			wfDebugLog( 'DiscordAuth', '[DiscordLinkStore] autoMigrateLegacyOptions error: ' . $e->getMessage() );
		}
	}

	/**
	 * Basic plausibility check for Discord IDs (snowflakes are numeric, 15-22 digits).
	 */
	public static function isValidDiscordId( string $discordId ): bool {
		return (bool)preg_match( '/^\d{15,22}$/', $discordId );
	}

	/**
	 * @param UserIdentity|int $user
	 */
	private static function toUserId( $user ): int {
		return $user instanceof UserIdentity ? (int)$user->getId() : (int)$user;
	}

	/**
	 * @param UserIdentity|int $user
	 * @param bool $fromPrimary Read from the primary database (use before writes)
	 * @return array|null [ 'discord_id' => string, 'discord_username' => string ] or null
	 */
	public function getLink( $user, bool $fromPrimary = false ): ?array {
		$userId = self::toUserId( $user );
		if ( $userId <= 0 ) {
			return null;
		}

		if ( !$fromPrimary && array_key_exists( $userId, $this->cache ) ) {
			return $this->cache[$userId] ?: null;
		}

		$this->ensureTable();

		$db = $fromPrimary
			? $this->dbProvider->getPrimaryDatabase()
			: $this->dbProvider->getReplicaDatabase();

		$row = $db->newSelectQueryBuilder()
			->select( [ 'dal_discord_id', 'dal_discord_username' ] )
			->from( self::TABLE )
			->where( [ 'dal_user' => $userId ] )
			->caller( __METHOD__ )
			->fetchRow();

		$link = $row ? [
			'discord_id' => (string)$row->dal_discord_id,
			'discord_username' => (string)$row->dal_discord_username,
		] : false;

		$this->cache[$userId] = $link;
		return $link ?: null;
	}

	/**
	 * @param UserIdentity|int $user
	 */
	public function getDiscordId( $user ): ?string {
		$link = $this->getLink( $user );
		return $link ? $link['discord_id'] : null;
	}

	/**
	 * @param UserIdentity|int $user
	 */
	public function getDiscordUsername( $user ): ?string {
		$link = $this->getLink( $user );
		return $link ? $link['discord_username'] : null;
	}

	/**
	 * Find the wiki user ID that is linked to the given Discord ID.
	 */
	public function getUserIdByDiscordId( string $discordId, bool $fromPrimary = false ): ?int {
		if ( $discordId === '' ) {
			return null;
		}

		$this->ensureTable();

		$db = $fromPrimary
			? $this->dbProvider->getPrimaryDatabase()
			: $this->dbProvider->getReplicaDatabase();

		$userId = $db->newSelectQueryBuilder()
			->select( 'dal_user' )
			->from( self::TABLE )
			->where( [ 'dal_discord_id' => $discordId ] )
			->caller( __METHOD__ )
			->fetchField();

		return $userId !== false ? (int)$userId : null;
	}

	/**
	 * Find the Discord ID linked to a wiki user, looked up by wiki user name.
	 */
	public function getDiscordIdByUserName( string $userName ): ?string {
		$this->ensureTable();

		$db = $this->dbProvider->getReplicaDatabase();
		$discordId = $db->newSelectQueryBuilder()
			->select( 'dal_discord_id' )
			->from( self::TABLE )
			->join( 'user', null, 'user_id = dal_user' )
			->where( [ 'user_name' => $userName ] )
			->caller( __METHOD__ )
			->fetchField();

		return $discordId !== false ? (string)$discordId : null;
	}

	/**
	 * All existing links.
	 *
	 * @return array<int,array> user ID => [ 'discord_id' => ..., 'discord_username' => ... ]
	 */
	public function getAllLinks(): array {
		$this->ensureTable();

		$res = $this->dbProvider->getReplicaDatabase()->newSelectQueryBuilder()
			->select( [ 'dal_user', 'dal_discord_id', 'dal_discord_username' ] )
			->from( self::TABLE )
			->caller( __METHOD__ )
			->fetchResultSet();

		$links = [];
		foreach ( $res as $row ) {
			$links[(int)$row->dal_user] = [
				'discord_id' => (string)$row->dal_discord_id,
				'discord_username' => (string)$row->dal_discord_username,
			];
		}
		return $links;
	}

	/**
	 * Link a wiki user to a Discord account (creates or replaces the user's link).
	 *
	 * @param UserIdentity|int $user
	 * @return bool False if the Discord ID is already linked to another wiki user
	 */
	public function linkUser( $user, string $discordId, string $discordUsername = '' ): bool {
		$userId = self::toUserId( $user );
		if ( $userId <= 0 || $discordId === '' ) {
			return false;
		}

		$otherUserId = $this->getUserIdByDiscordId( $discordId, true );
		if ( $otherUserId !== null && $otherUserId !== $userId ) {
			return false;
		}

		$dbw = $this->dbProvider->getPrimaryDatabase();
		$now = $dbw->timestamp();

		$dbw->startAtomic( __METHOD__ );
		$exists = (bool)$dbw->newSelectQueryBuilder()
			->select( 'dal_user' )
			->from( self::TABLE )
			->where( [ 'dal_user' => $userId ] )
			->forUpdate()
			->caller( __METHOD__ )
			->fetchField();

		if ( $exists ) {
			$dbw->newUpdateQueryBuilder()
				->update( self::TABLE )
				->set( [
					'dal_discord_id' => $discordId,
					'dal_discord_username' => $discordUsername,
					'dal_updated_at' => $now,
				] )
				->where( [ 'dal_user' => $userId ] )
				->caller( __METHOD__ )
				->execute();
		} else {
			$dbw->newInsertQueryBuilder()
				->insertInto( self::TABLE )
				->row( [
					'dal_user' => $userId,
					'dal_discord_id' => $discordId,
					'dal_discord_username' => $discordUsername,
					'dal_linked_at' => $now,
					'dal_updated_at' => $now,
				] )
				->caller( __METHOD__ )
				->execute();
		}
		$dbw->endAtomic( __METHOD__ );

		$this->cache[$userId] = [
			'discord_id' => $discordId,
			'discord_username' => $discordUsername,
		];

		wfDebugLog( 'DiscordAuth', sprintf( '[DiscordLinkStore] Linked user %d to Discord ID %s', $userId, $discordId ) );
		return true;
	}

	/**
	 * Update the stored Discord username (only if the user is linked and it changed).
	 *
	 * @param UserIdentity|int $user
	 */
	public function updateDiscordUsername( $user, string $discordUsername ): void {
		$userId = self::toUserId( $user );
		$link = $this->getLink( $userId, true );
		if ( !$link || $link['discord_username'] === $discordUsername ) {
			return;
		}

		$dbw = $this->dbProvider->getPrimaryDatabase();
		$dbw->newUpdateQueryBuilder()
			->update( self::TABLE )
			->set( [
				'dal_discord_username' => $discordUsername,
				'dal_updated_at' => $dbw->timestamp(),
			] )
			->where( [ 'dal_user' => $userId ] )
			->caller( __METHOD__ )
			->execute();

		$link['discord_username'] = $discordUsername;
		$this->cache[$userId] = $link;
	}

	/**
	 * Remove the Discord link of a wiki user.
	 *
	 * @param UserIdentity|int $user
	 */
	public function unlinkUser( $user ): void {
		$userId = self::toUserId( $user );
		if ( $userId <= 0 ) {
			return;
		}

		$this->ensureTable();

		$this->dbProvider->getPrimaryDatabase()->newDeleteQueryBuilder()
			->deleteFrom( self::TABLE )
			->where( [ 'dal_user' => $userId ] )
			->caller( __METHOD__ )
			->execute();

		$this->cache[$userId] = false;
		wfDebugLog( 'DiscordAuth', sprintf( '[DiscordLinkStore] Removed Discord link of user %d', $userId ) );
	}
}
