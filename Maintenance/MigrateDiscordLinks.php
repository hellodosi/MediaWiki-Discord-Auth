<?php
/**
 * Migrates Discord links from user_properties (discord_id / discord_username)
 * into the dedicated discordauth_links table.
 *
 * Runs automatically once via maintenance/update.php. It can also be run manually:
 *   php extensions/DiscordAuth/Maintenance/MigrateDiscordLinks.php [--force] [--keep-legacy] [--dry-run]
 */

namespace DiscordAuth\Maintenance;

use DiscordAuth\DiscordLinkStore;
use LoggedUpdateMaintenance;

$IP = getenv( 'MW_INSTALL_PATH' );
if ( $IP === false ) {
	$IP = __DIR__ . '/../../..';
}
require_once "$IP/maintenance/Maintenance.php";

class MigrateDiscordLinks extends LoggedUpdateMaintenance {

	public function __construct() {
		parent::__construct();
		$this->addDescription( 'Migrates Discord links from user_properties into the discordauth_links table.' );
		$this->addOption( 'keep-legacy', 'Do not delete migrated entries from user_properties' );
		$this->addOption( 'dry-run', 'Only report what would be done, do not write anything' );
		$this->requireExtension( 'DiscordAuth' );
	}

	protected function getUpdateKey() {
		return 'DiscordAuth-MigrateDiscordLinks';
	}

	protected function doDBUpdates() {
		$dbw = $this->getDB( DB_PRIMARY );
		$dryRun = $this->hasOption( 'dry-run' );
		$keepLegacy = $this->hasOption( 'keep-legacy' );

		if ( !$dbw->tableExists( DiscordLinkStore::TABLE, __METHOD__ ) ) {
			$this->error( 'Table ' . DiscordLinkStore::TABLE . ' does not exist. Please run update.php first.' );
			return false;
		}

		// Collect legacy data grouped by user
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

		$migrated = 0;
		$alreadyPresent = 0;
		$conflicts = 0;
		$orphans = 0;
		$cleanupUserIds = [];

		foreach ( $legacy as $userId => $props ) {
			$discordId = $props['discord_id'] ?? '';
			$discordUsername = $props['discord_username'] ?? '';

			if ( $discordId === '' ) {
				// Only a stale username without ID - just clean it up
				$cleanupUserIds[] = $userId;
				continue;
			}

			$userExists = (bool)$dbw->newSelectQueryBuilder()
				->select( 'user_id' )
				->from( 'user' )
				->where( [ 'user_id' => $userId ] )
				->caller( __METHOD__ )
				->fetchField();
			if ( !$userExists ) {
				$this->output( "  Skipping user ID $userId: user does not exist (Discord ID $discordId)\n" );
				$orphans++;
				$cleanupUserIds[] = $userId;
				continue;
			}

			$existingForUser = $dbw->newSelectQueryBuilder()
				->select( 'dal_discord_id' )
				->from( DiscordLinkStore::TABLE )
				->where( [ 'dal_user' => $userId ] )
				->caller( __METHOD__ )
				->fetchField();
			if ( $existingForUser !== false ) {
				// The new table always wins
				$alreadyPresent++;
				$cleanupUserIds[] = $userId;
				continue;
			}

			$ownerOfDiscordId = $dbw->newSelectQueryBuilder()
				->select( 'dal_user' )
				->from( DiscordLinkStore::TABLE )
				->where( [ 'dal_discord_id' => $discordId ] )
				->caller( __METHOD__ )
				->fetchField();
			if ( $ownerOfDiscordId !== false ) {
				$this->output( "  CONFLICT: Discord ID $discordId of user ID $userId is already linked to user ID $ownerOfDiscordId - skipped, legacy entry kept\n" );
				$conflicts++;
				continue;
			}

			if ( !$dryRun ) {
				$now = $dbw->timestamp();
				$dbw->newInsertQueryBuilder()
					->insertInto( DiscordLinkStore::TABLE )
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
			$migrated++;
			$cleanupUserIds[] = $userId;
		}

		if ( !$dryRun && !$keepLegacy && $cleanupUserIds ) {
			foreach ( array_chunk( $cleanupUserIds, 500 ) as $chunk ) {
				$dbw->newDeleteQueryBuilder()
					->deleteFrom( 'user_properties' )
					->where( [
						'up_user' => $chunk,
						'up_property' => [ 'discord_id', 'discord_username' ],
					] )
					->caller( __METHOD__ )
					->execute();
			}
		}

		$prefix = $dryRun ? '[DRY RUN] ' : '';
		$this->output( "{$prefix}Discord link migration finished: $migrated migrated, $alreadyPresent already present, "
			. "$conflicts conflicts, $orphans orphaned entries.\n" );
		if ( $conflicts > 0 ) {
			$this->output( "Please resolve the conflicts manually (e.g. via Special:LinkDiscord) and re-run this script with --force.\n" );
		}

		// In dry-run mode do not mark the update as done
		return !$dryRun;
	}
}

$maintClass = MigrateDiscordLinks::class;
require_once RUN_MAINTENANCE_IF_MAIN;
