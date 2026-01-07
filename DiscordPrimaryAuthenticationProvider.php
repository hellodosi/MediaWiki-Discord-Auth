<?php

namespace DiscordAuth;

use MediaWiki\Auth\AbstractPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Config\ConfigFactory;
use MediaWiki\Http\HttpRequestFactory;
use MediaWiki\User\User;
use MediaWiki\User\UserGroupManager;
use MWTimestamp;

class DiscordPrimaryAuthenticationProvider extends AbstractPrimaryAuthenticationProvider {

	/** @var HttpRequestFactory */
	private $httpRequestFactory;

	/** @var \Config */
	protected $config;

	/** @var UserGroupManager */
	private $userGroupManager;

	public function __construct(
		ConfigFactory $configFactory,
		HttpRequestFactory $httpRequestFactory,
		UserGroupManager $userGroupManager
	) {
		$this->config = $configFactory->makeConfig( 'main' );
		$this->httpRequestFactory = $httpRequestFactory;
		$this->userGroupManager = $userGroupManager;
	}

	public function getAuthenticationRequests( $action, array $options ): array {
		if ( $action === AuthManager::ACTION_LOGIN || $action === AuthManager::ACTION_CREATE ) {
			return [ new DiscordAuthenticationRequest() ];
		}
		return [];
	}

	public function beginPrimaryAuthentication( array $reqs ): AuthenticationResponse {
		$req = AuthenticationRequest::getRequestByClass( $reqs, DiscordAuthenticationRequest::class );
		if ( !$req ) {
			return AuthenticationResponse::newAbstain();
		}

		// Redirect to Discord
		$clientId = $this->config->get( 'DiscordClientId' );
		$redirectUri = $this->getRedirectUri();
		
		// Use a session-based state for CSRF protection
		$state = MWTimestamp::getInstance()->getTimestamp();
		$this->manager->getRequest()->getSession()->set( 'discord_auth_state', $state );

		$url = "https://discord.com/api/oauth2/authorize?" . http_build_query( [
			'client_id' => $clientId,
			'redirect_uri' => $redirectUri,
			'response_type' => 'code',
			'scope' => 'identify guilds.members.read',
			'state' => $state
		] );

		return AuthenticationResponse::newRedirect( [ new DiscordAuthenticationRequest() ], $url );
	}

	public function continuePrimaryAuthentication( array $reqs ): AuthenticationResponse {
		$req = AuthenticationRequest::getRequestByClass( $reqs, DiscordAuthenticationRequest::class );
		if ( !$req ) {
			return AuthenticationResponse::newAbstain();
		}

		$request = $this->manager->getRequest();
		$code = $request->getVal( 'code' );
		$state = $request->getVal( 'state' );
		$sessionState = $request->getSessionData( 'discord_auth_state' );

		if ( !$code || $state !== $sessionState ) {
			return AuthenticationResponse::newFail( wfMessage( 'discordauth-error-invalid-state' ) );
		}

		// Exchange code for token
		$tokenData = $this->exchangeCodeForToken( $code );
		if ( !$tokenData ) {
			return AuthenticationResponse::newFail( wfMessage( 'discordauth-error-token' ) );
		}

		$accessToken = $tokenData['access_token'];

		// Get Discord user info
		$discordUser = $this->getDiscordUser( $accessToken );
		if ( !$discordUser ) {
			return AuthenticationResponse::newFail( wfMessage( 'discordauth-error-userinfo' ) );
		}

		// Check server membership and roles
		$guildId = $this->config->get( 'DiscordGuildId' );
		$allowedRoles = $this->config->get( 'DiscordAllowedRoles' );

		$memberData = $this->getGuildMember( $accessToken, $guildId );
		wfDebugLog( 'DiscordAuth', 'Guild Member Data: ' . json_encode( $memberData ) );

		if ( !$memberData ) {
			return AuthenticationResponse::newFail( wfMessage( 'discordauth-error-not-member' ) );
		}

		$hasRole = false;
		if ( empty( $allowedRoles ) ) {
			$hasRole = true; // No roles defined, just server membership required
		} else {
			$userRoles = isset( $memberData['roles'] ) ? $memberData['roles'] : [];
			foreach ( $allowedRoles as $roleId ) {
				if ( in_array( $roleId, $userRoles ) ) {
					$hasRole = true;
					break;
				}
			}
		}

		if ( !$hasRole ) {
			return AuthenticationResponse::newFail( wfMessage( 'discordauth-error-no-role' ) );
		}

		// Authentication successful
		$username = $this->getWikiUsername( $discordUser );
		$user = User::newFromName( $username );

		$userRoles = $memberData['roles'] ?? [];

		if ( !$user || $user->getId() === 0 ) {
			if ( $this->manager->getAction() === AuthManager::ACTION_CREATE || $this->config->get( 'DiscordAutoCreate' ) ) {
				// Store roles in session for autoCreatedAccount to use
				$request->setSessionData( 'discord_roles_for_sync', $userRoles );
				// Create user if allowed
				return AuthenticationResponse::newPass( $username );
			}
			return AuthenticationResponse::newFail( wfMessage( 'discordauth-error-no-account' ) );
		}

		// Synchronize user groups based on Discord roles (only if mode is 'always')
		$syncMode = $this->config->get( 'DiscordGroupSyncMode' );
		wfDebugLog( 'DiscordAuth', sprintf(
			'Sync mode: %s, Will sync: %s',
			$syncMode,
			( $syncMode === 'always' ) ? 'YES' : 'NO'
		) );

		if ( $syncMode === 'always' ) {
			$this->syncUserGroups( $user, $userRoles );
		}

		// Set Discord authentication timestamp and enable remember me for persistent session
		$session = $request->getSession();
		$session->set( 'discord_last_auth', time() );
		$session->setRememberUser( true );
		$session->save();

		return AuthenticationResponse::newPass( $username );
	}

	private function exchangeCodeForToken( string $code ): ?array {
		$url = 'https://discord.com/api/oauth2/token';
		$params = [
			'client_id' => $this->config->get( 'DiscordClientId' ),
			'client_secret' => $this->config->get( 'DiscordClientSecret' ),
			'grant_type' => 'authorization_code',
			'code' => $code,
			'redirect_uri' => $this->getRedirectUri(),
		];

		$response = $this->httpRequestFactory->post( $url, [ 'postData' => $params ] );
		return $response ? json_decode( $response, true ) : null;
	}

	private function getDiscordUser( string $accessToken ): ?array {
		$url = 'https://discord.com/api/users/@me';
		$options = [
			'headers' => [ 'Authorization' => 'Bearer ' . $accessToken ]
		];
		$response = $this->httpRequestFactory->get( $url, $options );
		return $response ? json_decode( $response, true ) : null;
	}

	private function getGuildMember( string $accessToken, string $guildId ): ?array {
		$url = "https://discord.com/api/users/@me/guilds/$guildId/member";
		wfDebugLog( 'DiscordAuth', sprintf( 'Fetching guild member from: %s', $url ) );

		$options = [
			'headers' => [ 'Authorization' => 'Bearer ' . $accessToken ]
		];
		$response = $this->httpRequestFactory->get( $url, $options );

		if ( !$response ) {
			wfDebugLog( 'DiscordAuth', 'Failed to fetch guild member data - no response' );
			return null;
		}

		$data = json_decode( $response, true );
		wfDebugLog( 'DiscordAuth', 'Guild member response: ' . $response );

		return $data;
	}

	private function getRedirectUri(): string {
		return \SpecialPage::getTitleFor( 'UserLogin' )->getFullURL( [], false, PROTO_CANONICAL );
	}

	private function getWikiUsername( array $discordUser ): string {
		// Create a wiki-compatible username from Discord tag or ID
		// Discord usernames can have spaces and special chars, MediaWiki is stricter.
		return 'Discord:' . $discordUser['username'] . '#' . $discordUser['discriminator'];
	}

	public function accountCreationType(): string {
		return self::TYPE_CREATE;
	}

	public function testUserCanAuthenticate( $username ): bool {
		return true; // We check during the process
	}

	public function testUserExists( $username, $flags = User::READ_NORMAL ): bool {
		return User::newFromName( $username )->getId() > 0;
	}

	public function autoCreatedAccount( $user, $source ): void {
		// Synchronize groups for newly created accounts (if not disabled)
		$syncMode = $this->config->get( 'DiscordGroupSyncMode' );

		if ( $syncMode !== 'disabled' ) {
			// Get Discord roles from session (stored during continuePrimaryAuthentication)
			$request = $this->manager->getRequest();
			$discordRoles = $request->getSessionData( 'discord_roles_for_sync' );

			if ( $discordRoles ) {
				$this->syncUserGroups( $user, $discordRoles );
				// Clear from session
				$request->setSessionData( 'discord_roles_for_sync', null );
			}
		}
	}

	public function beginPrimaryAccountCreation( $user, $creator, array $reqs ) {
		// Account creation is handled by Discord authentication
		return AuthenticationResponse::newAbstain();
	}

	public function providerAllowsAuthenticationDataChange(
		AuthenticationRequest $req, $checkData = true
	) {
		// We don't support changing authentication data
		return \StatusValue::newGood( 'ignored' );
	}

	public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
		// We don't support changing authentication data
	}

	/**
	 * Synchronize MediaWiki user groups based on Discord roles
	 *
	 * @param User $user MediaWiki user object
	 * @param array $discordRoles Array of Discord role IDs the user has
	 * @return void
	 */
	private function syncUserGroups( User $user, array $discordRoles ): void {
		// Use $GLOBALS to avoid JSON parsing issues with large Discord IDs
		$roleToGroupMapping = $GLOBALS['wgDiscordRoleToGroupMapping'] ?? [];

		// If no mapping configured, skip synchronization
		if ( empty( $roleToGroupMapping ) ) {
			return;
		}

		// Debug logging
		wfDebugLog( 'DiscordAuth', sprintf(
			'Syncing groups for user %s with Discord roles: %s',
			$user->getName(),
			implode( ', ', $discordRoles )
		) );

		// Determine which groups the user should have based on their Discord roles
		$targetGroups = [];
		foreach ( $discordRoles as $roleId ) {
			// Ensure roleId is a string for comparison
			$roleId = (string)$roleId;

			// Check both string and potential numeric keys
			if ( isset( $roleToGroupMapping[$roleId] ) ) {
				$groups = $roleToGroupMapping[$roleId];
				wfDebugLog( 'DiscordAuth', sprintf(
					'Role %s maps to groups: %s',
					$roleId,
					is_array( $groups ) ? implode( ', ', $groups ) : $groups
				) );

				// Handle both string and array values
				if ( is_array( $groups ) ) {
					$targetGroups = array_merge( $targetGroups, $groups );
				} else {
					$targetGroups[] = $groups;
				}
			} else {
				wfDebugLog( 'DiscordAuth', sprintf(
					'Role %s not found in mapping',
					$roleId
				) );
			}
		}
		$targetGroups = array_unique( $targetGroups );

		// Get all groups that are managed by the mapping (to determine which to remove)
		$managedGroups = [];
		foreach ( $roleToGroupMapping as $groups ) {
			if ( is_array( $groups ) ) {
				$managedGroups = array_merge( $managedGroups, $groups );
			} else {
				$managedGroups[] = $groups;
			}
		}
		$managedGroups = array_unique( $managedGroups );

		// Get current user groups
		$currentGroups = $this->userGroupManager->getUserGroups( $user );

		wfDebugLog( 'DiscordAuth', sprintf(
			'Current groups: %s, Target groups: %s, Managed groups: %s',
			implode( ', ', $currentGroups ),
			implode( ', ', $targetGroups ),
			implode( ', ', $managedGroups )
		) );

		// Add missing groups
		foreach ( $targetGroups as $group ) {
			if ( !in_array( $group, $currentGroups ) ) {
				wfDebugLog( 'DiscordAuth', sprintf( 'Adding user %s to group: %s', $user->getName(), $group ) );
				$this->userGroupManager->addUserToGroup( $user, $group );
			}
		}

		// Remove groups that are managed but user no longer qualifies for
		foreach ( $managedGroups as $group ) {
			if ( in_array( $group, $currentGroups ) && !in_array( $group, $targetGroups ) ) {
				wfDebugLog( 'DiscordAuth', sprintf( 'Removing user %s from group: %s', $user->getName(), $group ) );
				$this->userGroupManager->removeUserFromGroup( $user, $group );
			}
		}
	}
}
