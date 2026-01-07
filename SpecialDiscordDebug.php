<?php

namespace DiscordAuth;

use MediaWiki\SpecialPage\SpecialPage;
use MediaWiki\Config\Config;

class SpecialDiscordDebug extends SpecialPage {

	/** @var Config */
	private $config;

	public function __construct( Config $config ) {
		parent::__construct( 'DiscordDebug', 'editinterface' );
		$this->config = $config;
	}

	public function execute( $par ) {
		$this->setHeaders();
		$output = $this->getOutput();

		$output->setPageTitle( 'Discord Auth Debug Info' );

		// Get configuration - use $GLOBALS for role mapping to avoid JSON parsing issues
		$roleMapping = $GLOBALS['wgDiscordRoleToGroupMapping'] ?? [];
		$syncMode = $this->config->get( 'DiscordGroupSyncMode' );
		$guildId = $this->config->get( 'DiscordGuildId' );

		$html = '<h2>Discord Auth Konfiguration</h2>';
		$html .= '<table class="wikitable">';
		$html .= '<tr><th>Setting</th><th>Value</th></tr>';
		$html .= '<tr><td>Sync Mode</td><td><code>' . htmlspecialchars( $syncMode ) . '</code></td></tr>';
		$html .= '<tr><td>Guild ID</td><td><code>' . htmlspecialchars( $guildId ) . '</code></td></tr>';
		$html .= '</table>';

		$html .= '<h2>Role to Group Mapping</h2>';

		// Show raw array dump for debugging
		$html .= '<details><summary>Raw Array Dump (für Debugging)</summary>';
		$html .= '<pre style="background: #f5f5f5; padding: 10px; overflow: auto;">';
		$html .= htmlspecialchars( print_r( $roleMapping, true ) );
		$html .= '</pre>';
		$html .= '<pre style="background: #f5f5f5; padding: 10px; overflow: auto;">';
		$html .= 'var_export: ' . htmlspecialchars( var_export( $roleMapping, true ) );
		$html .= '</pre>';
		$html .= '</details>';

		if ( empty( $roleMapping ) ) {
			$html .= '<p style="color: red;">⚠️ Keine Rollenzuordnung konfiguriert!</p>';
		} else {
			$html .= '<table class="wikitable">';
			$html .= '<tr><th>Discord Role ID</th><th>Key Type</th><th>Key (raw)</th><th>MediaWiki Groups</th><th>Value Type</th></tr>';
			foreach ( $roleMapping as $roleId => $groups ) {
				$html .= '<tr>';
				$html .= '<td><code>' . htmlspecialchars( $roleId ) . '</code></td>';
				$html .= '<td>' . htmlspecialchars( gettype( $roleId ) ) . '</td>';
				$html .= '<td><code>' . htmlspecialchars( var_export( $roleId, true ) ) . '</code></td>';
				if ( is_array( $groups ) ) {
					$html .= '<td>' . htmlspecialchars( implode( ', ', $groups ) ) . '</td>';
					$html .= '<td>Array (' . count( $groups ) . ' groups)</td>';
				} else {
					$html .= '<td>' . htmlspecialchars( $groups ) . '</td>';
					$html .= '<td>String</td>';
				}
				$html .= '</tr>';
			}
			$html .= '</table>';

			// Test lookup
			$html .= '<h3>Lookup Test</h3>';
			$testRoles = [ '1128644540346142780', '1128545620513259550' ];
			$html .= '<table class="wikitable">';
			$html .= '<tr><th>Test Role ID</th><th>Found?</th><th>Value</th></tr>';
			foreach ( $testRoles as $testRole ) {
				$html .= '<tr>';
				$html .= '<td><code>' . htmlspecialchars( $testRole ) . '</code></td>';
				if ( isset( $roleMapping[$testRole] ) ) {
					$html .= '<td style="color: green;">✓ YES</td>';
					$html .= '<td>' . htmlspecialchars( is_array( $roleMapping[$testRole] ) ? implode( ', ', $roleMapping[$testRole] ) : $roleMapping[$testRole] ) . '</td>';
				} else {
					$html .= '<td style="color: red;">✗ NO</td>';
					$html .= '<td>-</td>';
				}
				$html .= '</tr>';
			}
			$html .= '</table>';
		}

		// Check if groups exist
		$html .= '<h2>MediaWiki Gruppen Prüfung</h2>';
		$allMappedGroups = [];
		foreach ( $roleMapping as $groups ) {
			if ( is_array( $groups ) ) {
				$allMappedGroups = array_merge( $allMappedGroups, $groups );
			} else {
				$allMappedGroups[] = $groups;
			}
		}
		$allMappedGroups = array_unique( $allMappedGroups );

		$html .= '<table class="wikitable">';
		$html .= '<tr><th>Group Name</th><th>Status</th></tr>';

		global $wgGroupPermissions;
		foreach ( $allMappedGroups as $groupName ) {
			$html .= '<tr>';
			$html .= '<td><code>' . htmlspecialchars( $groupName ) . '</code></td>';
			if ( isset( $wgGroupPermissions[$groupName] ) ) {
				$html .= '<td style="color: green;">✓ Existiert</td>';
			} else {
				$html .= '<td style="color: orange;">⚠️ Nicht in $wgGroupPermissions definiert (wird aber trotzdem funktionieren)</td>';
			}
			$html .= '</tr>';
		}
		$html .= '</table>';

		$html .= '<h2>Debug Logging aktivieren</h2>';
		$html .= '<p>Fügen Sie folgende Zeile zu Ihrer <code>LocalSettings.php</code> hinzu um Debug-Logging zu aktivieren:</p>';
		$html .= '<pre style="background: #f5f5f5; padding: 10px; border-radius: 3px;">$wgDebugLogGroups[\'DiscordAuth\'] = \'/pfad/zu/debug.log\';</pre>';
		$html .= '<p>Dann können Sie die Logs in der Datei überprüfen um zu sehen was bei der Gruppen-Synchronisation passiert.</p>';

		$output->addHTML( $html );
	}

	protected function getGroupName() {
		return 'wiki';
	}
}
