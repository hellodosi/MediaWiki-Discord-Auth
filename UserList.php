<?php

namespace DiscordAuth;

use MediaWiki\MediaWikiServices;
use Parser;
use PPFrame;
use Title;

class UserList {

	public static function renderUserList( ?string $input, array $args, Parser $parser, PPFrame $frame ) {
		$group = trim( $args['group'] ?? '' );
		$usersArg = trim( $args['users'] ?? '' );
		$excludeArg = trim( $args['exclude'] ?? '' );
		$showArg = trim( $args['show'] ?? 'name' );
		$fallbackImage = trim( $args['fallbackimage'] ?? 'Person.jpg' );
		$displayNameType = trim( $args['displayname'] ?? 'real' );
		$layout = trim( $args['layout'] ?? 'card' );

		$showFields = self::parseCsv( $showArg );

		if ( $usersArg !== '' && $usersArg !== '*' ) {
			$usernames = self::parseCsv( $usersArg );
		} elseif ( $group !== '' && $group !== '*' && strtolower( $group ) !== 'all' ) {
			$usernames = self::getUsersInGroup( $group );
		} else {
			$usernames = self::getAllUsers();
		}

		// Exclude specified users
		$excludeUsers = array_map( 'mb_strtolower', self::parseCsv( $excludeArg ) );
		if ( !empty( $excludeUsers ) ) {
			$usernames = array_filter( $usernames, static function ( $u ) use ( $excludeUsers ) {
				return !in_array( mb_strtolower( $u ), $excludeUsers, true );
			} );
		}

		if ( !$usernames ) {
			return [
				self::getInlineCss() . '<div class="ul-empty">Keine Benutzer gefunden.</div>',
				'isHTML' => true, 'noparse' => true
			];
		}

		$html = self::getInlineCss();
		if ( $layout === 'list' ) {
			$html .= '<div class="ul-wrapper"><div class="ul-list-container">';
			foreach ( $usernames as $username ) {
				$profile = self::getUserProfileData( $username );
				$html .= self::renderListRow( $username, $profile, $showFields, $fallbackImage );
			}
		} else {
			$html .= '<div class="ul-wrapper"><div class="ul-grid">';
			foreach ( $usernames as $username ) {
				$profile = self::getUserProfileData( $username );
				$html .= self::renderCard( $username, $profile, $showFields, $fallbackImage, $displayNameType );
			}
		}

		$html .= '</div></div>';

		return [ $html, 'isHTML' => true, 'noparse' => true ];
	}

	private static function parseCsv( string $value ): array {
		$parts = array_map( 'trim', explode( ',', $value ) );
		return array_values( array_filter( $parts, static fn ( $v ) => $v !== '' ) );
	}

	private static function getUsersInGroup( string $group ): array {
		$services = MediaWikiServices::getInstance();
		$db = method_exists( $services, 'getConnectionProvider' ) 
			? $services->getConnectionProvider()->getReplicaDatabase() 
			: wfGetDB( DB_REPLICA );

		$usernames = [];
		$res = $db->newSelectQueryBuilder()
			->select( [ 'user_name' ] )
			->from( 'user' )
			->join( 'user_groups', null, 'ug_user = user_id' )
			->where( [ 'ug_group' => $group ] )
			->orderBy( 'user_name', 'ASC' )
			->caller( __METHOD__ )
			->fetchResultSet();

		foreach ( $res as $row ) {
			$usernames[] = $row->user_name;
		}
		return $usernames;
	}

	private static function getAllUsers(): array {
		$services = MediaWikiServices::getInstance();
		$db = method_exists( $services, 'getConnectionProvider' ) 
			? $services->getConnectionProvider()->getReplicaDatabase() 
			: wfGetDB( DB_REPLICA );

		$usernames = [];
		$res = $db->newSelectQueryBuilder()
			->select( [ 'user_name' ] )
			->from( 'user' )
			->orderBy( 'user_name', 'ASC' )
			->caller( __METHOD__ )
			->fetchResultSet();

		foreach ( $res as $row ) {
			$usernames[] = $row->user_name;
		}
		return $usernames;
	}

	private static function getUserProfileData( string $username ): array {
		$title = Title::makeTitle( NS_USER, $username );
		if ( !$title || !$title->exists() ) return [];

		$wikiPage = MediaWikiServices::getInstance()->getWikiPageFactory()->newFromTitle( $title );
		$content = $wikiPage->getContent();
		return $content ? self::extractInfoboxParams( $content->getText() ) : [];
	}

	private static function extractInfoboxParams( string $text ): array {
		$data = [];
		$lines = preg_split( "/\r\n|\n|\r/", $text );
		$inInfobox = false;
		foreach ( $lines as $line ) {
			$trimmed = trim( $line );
			if ( !$inInfobox ) {
				if ( preg_match( '/^\{\{\s*Benutzerinfobox\b/i', $trimmed ) ) $inInfobox = true;
				continue;
			}
			if ( preg_match( '/^\}\}\s*$/', $trimmed ) ) break;
			if ( preg_match( '/^\|\s*([^=|]+?)\s*=\s*(.*)$/', $line, $m ) ) {
				$data[trim( mb_strtolower( $m[1] ) )] = trim( $m[2] );
			}
		}
		return $data;
	}

	private static function renderCard( $username, $profile, $showFields, $fallbackImage, $displayNameType ): string {
		$userPageTitle = Title::makeTitle( NS_USER, $username );
		$userPageUrl = $userPageTitle ? $userPageTitle->getLocalURL() : '#';

		$image = self::firstNonEmptyValue( $profile, [ 'bild', 'image', 'foto' ] ) ?: $fallbackImage;
		$realName = self::firstNonEmptyValue( $profile, [ 'name', 'realname' ] ) ?: $username;
		$mail = self::firstNonEmptyValue( $profile, [ 'mail', 'email' ] );
		$discordId = self::getDiscordIdForUser( $username );

		$html = '<div class="ul-card">';
		
		// Avatar
		$html .= '<div class="ul-avatar"><a href="'.htmlspecialchars($userPageUrl).'">' . self::renderWikiFile($image, 120, $realName) . '</a></div>';
		
		// Name & Info
		$html .= '<div class="ul-info">';
		$title = ($displayNameType === 'wiki') ? $username : $realName;
		$html .= '<div class="ul-name"><a href="'.htmlspecialchars($userPageUrl).'">'.htmlspecialchars($title).'</a></div>';
		if ($displayNameType === 'both' && $realName !== $username) {
			$html .= '<div class="ul-sub">('.htmlspecialchars($username).')</div>';
		}

		// Felder
		foreach ( $showFields as $field ) {
			$v = $profile[mb_strtolower(trim($field))] ?? '';
			if ($v !== '' && !in_array(mb_strtolower($field), ['name','mail','email','discord'])) {
				$html .= '<div class="ul-text">'.nl2br(htmlspecialchars($v)).'</div>';
			}
		}

		// Buttons
		if ( $discordId !== '' || $mail !== '' ) {
			$html .= '<div class="ul-actions plainlinks">';
			if ( $discordId !== '' ) {
				$html .= '<a class="ul-btn" href="https://discord.com/users/'.rawurlencode($discordId).'" target="_blank" rel="noopener" title="Discord"><span class="ul-icon-circle">'.self::getIcon('discord').'</span></a>';
			}
			if ( $mail !== '' ) {
				$html .= '<a class="ul-btn" href="mailto:'.htmlspecialchars($mail).'" title="E-Mail"><span class="ul-icon-circle">'.self::getIcon('mail').'</span></a>';
			}
			$html .= '</div>';
		}

		$html .= '</div></div>';
		return $html;
	}

	private static function renderListRow( $username, $profile, $showFields, $fallbackImage ): string {
		$userPageTitle = Title::makeTitle( NS_USER, $username );
		$userPageUrl = $userPageTitle ? $userPageTitle->getLocalURL() : '#';

		$image = self::firstNonEmptyValue( $profile, [ 'bild', 'image', 'foto' ] ) ?: $fallbackImage;
		$realName = self::firstNonEmptyValue( $profile, [ 'name', 'realname' ] );
		$mail = self::firstNonEmptyValue( $profile, [ 'mail', 'email' ] );
		$discordId = self::getDiscordIdForUser( $username );

		$html = '<div class="ul-list-row">';

		// Spalte 1: Kleines Bild links
		$html .= '<div class="ul-list-avatar"><a href="' . htmlspecialchars( $userPageUrl ) . '">' . self::renderWikiFile( $image, 50, $realName ?: $username ) . '</a></div>';

		// Spalte 2: Name und sekundäre Info
		$html .= '<div class="ul-list-info">';
		$displayName = htmlspecialchars( $username );
		if ( $realName !== '' ) {
			$displayName .= ' <span class="ul-list-realname">(' . htmlspecialchars( $realName ) . ')</span>';
		}
		$html .= '<div class="ul-list-name"><a href="' . htmlspecialchars( $userPageUrl ) . '">' . $displayName . '</a></div>';

		// Unter dem Namen sekundäre Information
		$secondaryInfo = [];
		foreach ( $showFields as $field ) {
			$v = $profile[mb_strtolower(trim($field))] ?? '';
			if ( $v !== '' && !in_array( mb_strtolower( $field ), [ 'name', 'mail', 'email', 'discord' ] ) ) {
				$secondaryInfo[] = htmlspecialchars( $v );
			}
		}
		if ( !empty( $secondaryInfo ) ) {
			$html .= '<div class="ul-list-secondary">' . implode( ' • ', $secondaryInfo ) . '</div>';
		}
		$html .= '</div>';

		// Spalte 3: Symbole für Discord und Mail
		$html .= '<div class="ul-list-actions plainlinks">';
		if ( $discordId !== '' ) {
			$html .= '<a class="ul-btn" href="https://discord.com/users/' . rawurlencode( $discordId ) . '" target="_blank" rel="noopener" title="Discord"><span class="ul-icon-circle">' . self::getIcon( 'discord' ) . '</span></a>';
		}
		if ( $mail !== '' ) {
			$html .= '<a class="ul-btn" href="mailto:' . htmlspecialchars( $mail ) . '" title="E-Mail"><span class="ul-icon-circle">' . self::getIcon( 'mail' ) . '</span></a>';
		}
		$html .= '</div>';

		$html .= '</div>';
		return $html;
	}

	private static function renderWikiFile( string $filename, int $width, string $alt = '' ): string {
		$title = Title::makeTitleSafe( NS_FILE, $filename );
		$file = $title ? MediaWikiServices::getInstance()->getRepoGroup()->findFile( $title ) : null;
		if ( !$file ) return '<div class="ul-no-img"></div>';
		$thumb = $file->transform( [ 'width' => $width ] );
		return $thumb ? '<img src="'.htmlspecialchars($thumb->getUrl()).'" alt="'.htmlspecialchars($alt).'">' : '';
	}

	private static function firstNonEmptyValue( array $data, array $keys ): string {
		foreach ($keys as $k) { if (isset($data[$k]) && trim($data[$k]) !== '') return trim($data[$k]); }
		return '';
	}

	private static function getIcon($type): string {
		$icons = [
			'discord' => '<svg width="20" height="20" viewBox="0 0 24 24"><path d="M20.317 4.369A19.791 19.791 0 0 0 15.885 3c-.191.328-.403.77-.552 1.116a18.27 18.27 0 0 0-6.666 0A12.64 12.64 0 0 0 8.115 3a19.736 19.736 0 0 0-4.435 1.371C.533 9.067-.32 13.63.099 18.129a19.9 19.9 0 0 0 5.993 3.029c.483-.665.913-1.37 1.282-2.11a12.955 12.955 0 0 1-2.017-.97c.169-.124.334-.252.495-.385 3.89 1.78 8.107 1.78 11.95 0 .163.133.328.261.495.385a12.92 12.92 0 0 1-2.021.972c.37.738.8 1.443 1.284 2.108a19.86 19.86 0 0 0 5.995-3.029c.5-5.216-.838-9.737-3.238-13.76ZM8.02 15.331c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.211 0 2.176 1.095 2.157 2.419 0 1.334-.955 2.419-2.157 2.419Zm7.974 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.211 0 2.176 1.095 2.157 2.419 0 1.334-.946 2.419-2.157 2.419Z"/></svg>',
			'mail' => '<svg width="20" height="20" viewBox="0 0 24 24"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2Zm0 4-8 5-8-5V6l8 5 8-5v2Z"/></svg>'
		];
		return $icons[$type] ?? '';
	}

	private static function getDiscordIdForUser( string $username ): string {
		$services = MediaWikiServices::getInstance();
		$db = method_exists( $services, 'getConnectionProvider' ) ? $services->getConnectionProvider()->getReplicaDatabase() : wfGetDB( DB_REPLICA );
		$row = $db->newSelectQueryBuilder()->select(['up_value'])->from('user_properties')->join('user', null, 'user_id = up_user')->where(['user_name' => $username, 'up_property' => 'discord_id'])->fetchRow();
		return $row ? trim((string)$row->up_value) : '';
	}

	private static function getInlineCss(): string {
		return '<style>
.mw-parser-output .ul-wrapper { width: 100%; clear: both; display: block; }
.mw-parser-output .ul-grid {
	display: grid;
	grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
	gap: 20px; margin: 1.5em 0;
}
.mw-parser-output .ul-card {
	background: #fff !important; border: 1px solid #e1e8ed !important; border-radius: 12px !important;
	padding: 24px 15px !important; text-align: center !important; display: flex !important;
	flex-direction: column !important; align-items: center !important; box-shadow: 0 2px 8px rgba(0,0,0,0.05) !important;
}
.mw-parser-output .ul-avatar img {
	width: 100px !important; height: 100px !important; border-radius: 50% !important;
	object-fit: cover !important; border: 3px solid #f8f9fa !important;
}
.mw-parser-output .ul-name { font-size: 1.1rem; font-weight: 700; margin: 10px 0 2px; }
.mw-parser-output .ul-name a { color: #333 !important; text-decoration: none !important; }
.mw-parser-output .ul-sub { font-size: 0.85rem; color: #888; margin-bottom: 8px; }
.mw-parser-output .ul-text { font-size: 0.9rem; color: #555; line-height: 1.4; }

.mw-parser-output .ul-actions { display: flex !important; gap: 12px !important; margin-top: auto !important; padding-top: 15px !important; }

/* Basis-Link */
.mw-parser-output .ul-actions a.ul-btn {
	background: none !important;
	padding: 0 !important;
	margin: 0 !important;
	text-decoration: none !important;
	border: none !important;
	display: inline-block !important;
	outline: none !important;
}

/* Der Kreis */
.mw-parser-output .ul-icon-circle {
	width: 40px !important; 
	height: 40px !important; 
	border-radius: 50% !important;
	background-color: #f1f4f8 !important; /* Hellgrau */
	border: 1px solid #d1d9e1 !important;
	display: flex !important; 
	align-items: center !important; 
	justify-content: center !important;
	color: #444 !important;
	transition: all 0.2s ease !important;
	box-shadow: 0 1px 3px rgba(0,0,0,0.1) !important;
}

.mw-parser-output .ul-btn:hover .ul-icon-circle { 
	background-color: #e2e8f0 !important;
	border-color: #bcc6d1 !important;
	transform: translateY(-1px);
}

/* SVG Größe im Kreis erzwingen */
.mw-parser-output .ul-icon-circle svg { 
	width: 20px !important; 
	height: 20px !important; 
	min-width: 20px !important;
	min-height: 20px !important;
	fill: currentColor !important; 
	display: block !important;
}

/* Pseudo-Elemente des Links radikal ausschalten */
.mw-parser-output .ul-btn::before,
.mw-parser-output .ul-btn::after {
	content: none !important;
	display: none !important;
}

.ul-empty, .ul-error { padding: 15px; background: #fff3cd; border: 1px solid #ffe69c; border-radius: 8px; }

/* List Layout Styles */
.mw-parser-output .ul-list-container {
	display: grid !important;
	grid-template-columns: 1fr 1fr !important;
	gap: 12px !important;
	margin: 1.5em 0 !important;
	width: 100% !important;
}
@media (max-width: 600px) {
	.mw-parser-output .ul-list-container {
		grid-template-columns: 1fr !important;
	}
}
.mw-parser-output .ul-list-row {
	display: flex !important;
	align-items: center !important;
	background: #fff !important;
	border: 1px solid #e1e8ed !important;
	border-radius: 12px !important;
	padding: 12px 20px !important;
	box-shadow: 0 2px 8px rgba(0,0,0,0.05) !important;
}
.mw-parser-output .ul-list-avatar img {
	width: 50px !important;
	height: 50px !important;
	border-radius: 50% !important;
	object-fit: cover !important;
	border: 2px solid #f8f9fa !important;
}
.mw-parser-output .ul-list-avatar .ul-no-img {
	width: 50px !important;
	height: 50px !important;
	border-radius: 50% !important;
	background: #eee !important;
	border: 2px solid #f8f9fa !important;
}
.mw-parser-output .ul-list-info {
	flex-grow: 1 !important;
	margin-left: 15px !important;
	display: flex !important;
	flex-direction: column !important;
	align-items: flex-start !important;
	text-align: left !important;
}
.mw-parser-output .ul-list-name {
	font-size: 1.05rem !important;
	font-weight: 700 !important;
	margin: 0 !important;
}
.mw-parser-output .ul-list-name a {
	color: #333 !important;
	text-decoration: none !important;
}
.mw-parser-output .ul-list-realname {
	font-size: 0.9rem !important;
	font-weight: normal !important;
	color: #666 !important;
	margin-left: 5px !important;
}
.mw-parser-output .ul-list-secondary {
	font-size: 0.85rem !important;
	font-weight: 300 !important;
	color: #777 !important;
	margin-top: 3px !important;
	line-height: 1.3 !important;
}
.mw-parser-output .ul-list-actions {
	display: flex !important;
	gap: 10px !important;
	margin-left: auto !important;
	align-items: center !important;
	padding-top: 0 !important;
	margin-top: 0 !important;
}
</style>';
	}
}
