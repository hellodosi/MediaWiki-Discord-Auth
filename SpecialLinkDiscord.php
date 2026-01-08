<?php

namespace DiscordAuth;

use MediaWiki\SpecialPage\SpecialPage;
use MediaWiki\Config\Config;
use MediaWiki\Http\HttpRequestFactory;
use MediaWiki\User\UserOptionsLookup;
use MediaWiki\User\UserOptionsManager;
use MediaWiki\User\UserGroupManager;

class SpecialLinkDiscord extends SpecialPage {

	/** @var Config */
	private $config;

	/** @var HttpRequestFactory */
	private $httpRequestFactory;

	/** @var UserOptionsLookup */
	private $userOptionsLookup;

	/** @var UserOptionsManager */
	private $userOptionsManager;

	/** @var UserGroupManager */
	private $userGroupManager;

	public function __construct(
		Config $config,
		HttpRequestFactory $httpRequestFactory,
		UserOptionsLookup $userOptionsLookup,
		UserOptionsManager $userOptionsManager,
		UserGroupManager $userGroupManager
	) {
		parent::__construct( 'LinkDiscord' );
		$this->config = $config;
		$this->httpRequestFactory = $httpRequestFactory;
		$this->userOptionsLookup = $userOptionsLookup;
		$this->userOptionsManager = $userOptionsManager;
		$this->userGroupManager = $userGroupManager;
	}

	public function execute( $par ) {
		$request = $this->getRequest();
		$output = $this->getOutput();
		$user = $this->getUser();
		$this->setHeaders();

		// User must be logged in
		if ( !$user->isRegistered() ) {
			$output->addHTML( '<div class="error">' . $this->msg( 'discordauth-link-not-logged-in' )->escaped() . '</div>' );
			return;
		}

		// Check if already linked
		$existingDiscordId = $this->userOptionsLookup->getOption( $user, 'discord_id' );

		// Handle unlinking
		if ( $request->getVal( 'action' ) === 'unlink' && $existingDiscordId ) {
			if ( $request->wasPosted() && $user->matchEditToken( $request->getVal( 'token' ) ) ) {
				$this->userOptionsManager->setOption( $user, 'discord_id', null );
				$this->userOptionsManager->saveOptions( $user );
				$output->addHTML( '<div class="success" style="padding: 10px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 5px; color: #155724; margin: 20px 0;">'
					. $this->msg( 'discordauth-unlink-success' )->escaped() . '</div>' );
				$existingDiscordId = null;
			} else {
				$this->showUnlinkConfirmation( $existingDiscordId );
				return;
			}
		}

		if ( $existingDiscordId ) {
			$this->showAlreadyLinked( $existingDiscordId );
			return;
		}

		// Check if we're returning from Discord
		$code = $request->getVal( 'code' );
		$state = $request->getVal( 'state' );
		$error = $request->getVal( 'error' );

		if ( $error ) {
			$output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-oauth', $error )->escaped() . '</div>' );
			$this->showLinkForm();
			return;
		}

		if ( $code ) {
			$this->handleCallback( $code, $state );
			return;
		}

		// Check if user clicked "Start Link" button
		if ( $request->wasPosted() && $request->getVal( 'start_link' ) ) {
			$this->redirectToDiscord();
			return;
		}

		// Show link form
		$this->showLinkForm();
	}

	private function showLinkForm() {
		$output = $this->getOutput();
		$linkUrl = $this->getPageTitle()->getFullURL();

		$output->addHTML( '
			<div style="max-width: 600px; margin: 30px auto; padding: 30px; background: #f8f9fa; border-radius: 10px;">
				<h2 style="color: #5865F2; margin-top: 0;">' . $this->msg( 'discordauth-link-header' )->escaped() . '</h2>
				<p>' . $this->msg( 'discordauth-link-text' )->escaped() . '</p>

				<ul style="margin: 20px 0; padding-left: 20px;">
					<li>' . $this->msg( 'discordauth-link-benefit-1' )->escaped() . '</li>
					<li>' . $this->msg( 'discordauth-link-benefit-2' )->escaped() . '</li>
					<li>' . $this->msg( 'discordauth-link-benefit-3' )->escaped() . '</li>
				</ul>

				<form method="post" action="' . htmlspecialchars( $linkUrl ) . '">
					<button type="submit"
							name="start_link"
							value="1"
							style="width: 100%;
								   background: #5865F2;
								   color: white;
								   padding: 15px;
								   border: none;
								   border-radius: 5px;
								   font-size: 16px;
								   font-weight: bold;
								   cursor: pointer;">
						<svg style="width: 20px; height: 20px; vertical-align: middle; margin-right: 8px;" viewBox="0 0 71 55" fill="none" xmlns="http://www.w3.org/2000/svg">
							<path d="M60.1045 4.8978C55.5792 2.8214 50.7265 1.2916 45.6527 0.41542C45.5603 0.39851 45.468 0.440769 45.4204 0.525289C44.7963 1.6353 44.105 3.0834 43.6209 4.2216C38.1637 3.4046 32.7345 3.4046 27.3892 4.2216C26.905 3.0581 26.1886 1.6353 25.5617 0.525289C25.5141 0.443589 25.4218 0.40133 25.3294 0.41542C20.2584 1.2888 15.4057 2.8186 10.8776 4.8978C10.8384 4.9147 10.8048 4.9429 10.7825 4.9795C1.57795 18.7309 -0.943561 32.1443 0.293408 45.3914C0.299005 45.4562 0.335386 45.5182 0.385761 45.5576C6.45866 50.0174 12.3413 52.7249 18.1147 54.5195C18.2071 54.5477 18.305 54.5139 18.3638 54.4378C19.7295 52.5728 20.9469 50.6063 21.9907 48.5383C22.0523 48.4172 21.9935 48.2735 21.8676 48.2256C19.9366 47.4931 18.0979 46.6 16.3292 45.5858C16.1893 45.5041 16.1781 45.304 16.3068 45.2082C16.679 44.9293 17.0513 44.6391 17.4067 44.3461C17.471 44.2926 17.5606 44.2813 17.6362 44.3151C29.2558 49.6202 41.8354 49.6202 53.3179 44.3151C53.3935 44.2785 53.4831 44.2898 53.5502 44.3433C53.9057 44.6363 54.2779 44.9293 54.6529 45.2082C54.7816 45.304 54.7732 45.5041 54.6333 45.5858C52.8646 46.6197 51.0259 47.4931 49.0921 48.2228C48.9662 48.2707 48.9102 48.4172 48.9718 48.5383C50.038 50.6034 51.2554 52.5699 52.5959 54.435C52.6519 54.5139 52.7526 54.5477 52.845 54.5195C58.6464 52.7249 64.529 50.0174 70.6019 45.5576C70.6551 45.5182 70.6887 45.459 70.6943 45.3942C72.1747 30.0791 68.2147 16.7757 60.1968 4.9823C60.1772 4.9429 60.1437 4.9147 60.1045 4.8978ZM23.7259 37.3253C20.2276 37.3253 17.3451 34.1136 17.3451 30.1693C17.3451 26.225 20.1717 23.0133 23.7259 23.0133C27.308 23.0133 30.1626 26.2532 30.1066 30.1693C30.1066 34.1136 27.28 37.3253 23.7259 37.3253ZM47.3178 37.3253C43.8196 37.3253 40.9371 34.1136 40.9371 30.1693C40.9371 26.225 43.7636 23.0133 47.3178 23.0133C50.9 23.0133 53.7545 26.2532 53.6986 30.1693C53.6986 34.1136 50.9 37.3253 47.3178 37.3253Z" fill="currentColor"/>
						</svg>
						' . $this->msg( 'discordauth-link-button' )->escaped() . '
					</button>
				</form>
			</div>
		' );
	}

	private function showAlreadyLinked( $discordId ) {
		$output = $this->getOutput();
		$user = $this->getUser();
		$unlinkUrl = $this->getPageTitle()->getFullURL( [ 'action' => 'unlink' ] );

		$output->addHTML( '
			<div style="max-width: 600px; margin: 30px auto; padding: 30px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 10px;">
				<h2 style="color: #155724; margin-top: 0;">✓ ' . $this->msg( 'discordauth-already-linked-header' )->escaped() . '</h2>
				<p>' . $this->msg( 'discordauth-already-linked-text' )->escaped() . '</p>
				<p style="font-family: monospace; background: white; padding: 10px; border-radius: 5px;">
					<strong>Discord ID:</strong> ' . htmlspecialchars( $discordId ) . '
				</p>

				<a href="' . htmlspecialchars( $unlinkUrl ) . '"
				   style="display: inline-block;
						  background: #dc3545;
						  color: white;
						  padding: 10px 20px;
						  text-decoration: none;
						  border-radius: 5px;
						  margin-top: 20px;">
					' . $this->msg( 'discordauth-unlink-button' )->escaped() . '
				</a>
			</div>
		' );
	}

	private function showUnlinkConfirmation( $discordId ) {
		$output = $this->getOutput();
		$user = $this->getUser();

		$output->addHTML( '
			<div style="max-width: 600px; margin: 30px auto; padding: 30px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 10px;">
				<h2 style="color: #856404; margin-top: 0;">⚠️ ' . $this->msg( 'discordauth-unlink-confirm-header' )->escaped() . '</h2>
				<p>' . $this->msg( 'discordauth-unlink-confirm-text' )->escaped() . '</p>

				<form method="post" action="' . $this->getPageTitle()->getFullURL() . '">
					<input type="hidden" name="action" value="unlink">
					<input type="hidden" name="token" value="' . htmlspecialchars( $user->getEditToken() ) . '">

					<button type="submit"
							style="background: #dc3545;
								   color: white;
								   padding: 10px 20px;
								   border: none;
								   border-radius: 5px;
								   font-weight: bold;
								   cursor: pointer;
								   margin-right: 10px;">
						' . $this->msg( 'discordauth-unlink-confirm-button' )->escaped() . '
					</button>

					<a href="' . $this->getPageTitle()->getFullURL() . '"
					   style="display: inline-block;
							  background: #6c757d;
							  color: white;
							  padding: 10px 20px;
							  text-decoration: none;
							  border-radius: 5px;">
						' . $this->msg( 'discordauth-unlink-cancel-button' )->escaped() . '
					</a>
				</form>
			</div>
		' );
	}

	private function handleCallback( $code, $state ) {
		$output = $this->getOutput();
		$request = $this->getRequest();
		$session = $request->getSession();
		$user = $this->getUser();

		// Verify state
		$sessionState = $session->get( 'discord_link_state' );
		if ( !$state || $state !== $sessionState ) {
			$output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-invalid-state' )->escaped() . '</div>' );
			return;
		}

		// Clear state
		$session->remove( 'discord_link_state' );

		// Exchange code for token
		$tokenData = $this->exchangeCodeForToken( $code );
		if ( !$tokenData || !isset( $tokenData['access_token'] ) ) {
			$output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-token' )->escaped() . '</div>' );
			return;
		}

		$accessToken = $tokenData['access_token'];

		// Get Discord user info
		$discordUser = $this->getDiscordUser( $accessToken );
		if ( !$discordUser || !isset( $discordUser['id'] ) ) {
			$output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-userinfo' )->escaped() . '</div>' );
			return;
		}

		$discordId = $discordUser['id'];

		// Check if this Discord account is already linked to another user
		$existingUser = $this->getUserByDiscordId( $discordId );
		if ( $existingUser && $existingUser->getId() !== $user->getId() ) {
			$output->addHTML( '<div class="error">' . $this->msg( 'discordauth-link-already-linked-other' )->escaped() . '</div>' );
			return;
		}

		// Link the account
		$this->userOptionsManager->setOption( $user, 'discord_id', $discordId );
		$this->userOptionsManager->setOption( $user, 'discord_username', $discordUser['username'] );
		$this->userOptionsManager->saveOptions( $user );

		// Synchronize user groups based on Discord roles (only if mode is 'always')
		$syncMode = $this->config->get( 'DiscordGroupSyncMode' );
		wfDebugLog( 'DiscordAuth', sprintf(
			'[LinkDiscord] Sync mode: %s, Will sync: %s',
			$syncMode,
			( $syncMode === 'always' ) ? 'YES' : 'NO'
		) );

		if ( $syncMode === 'always' ) {
			$guildId = $this->config->get( 'DiscordGuildId' );
			if ( $guildId ) {
				$memberData = $this->getGuildMember( $accessToken, $guildId );
				if ( $memberData && isset( $memberData['roles'] ) ) {
					$this->syncUserGroups( $user, $memberData['roles'] );
				}
			}
		}

		$output->addHTML( '
			<div class="success" style="max-width: 600px; margin: 30px auto; padding: 30px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 10px; color: #155724;">
				<h2 style="margin-top: 0;">✓ ' . $this->msg( 'discordauth-link-success-header' )->escaped() . '</h2>
				<p>' . $this->msg( 'discordauth-link-success-text', htmlspecialchars( $discordUser['username'] ) )->parse() . '</p>
				<p>' . $this->msg( 'discordauth-link-success-hint' )->escaped() . '</p>
			</div>
		' );
	}

	public function doesWrites() {
		return true;
	}

	protected function getGroupName() {
		return 'users';
	}

	private function exchangeCodeForToken( $code ) {
		$url = 'https://discord.com/api/oauth2/token';
		$params = [
			'client_id' => $this->config->get( 'DiscordClientId' ),
			'client_secret' => $this->config->get( 'DiscordClientSecret' ),
			'grant_type' => 'authorization_code',
			'code' => $code,
			'redirect_uri' => $this->getRedirectUri(),
		];

		$options = [
			'method' => 'POST',
			'postData' => http_build_query( $params ),
		];

		$response = $this->httpRequestFactory->request( 'POST', $url, $options );
		if ( !$response ) {
			return null;
		}

		return json_decode( $response, true );
	}

	private function getDiscordUser( $accessToken ) {
		$url = 'https://discord.com/api/users/@me';
		$options = [
			'method' => 'GET',
		];

		$request = $this->httpRequestFactory->create( $url, $options );
		$request->setHeader( 'Authorization', 'Bearer ' . $accessToken );
		$status = $request->execute();

		if ( !$status->isOK() ) {
			return null;
		}

		return json_decode( $request->getContent(), true );
	}

	private function getUserByDiscordId( $discordId ) {
		$dbr = wfGetDB( DB_REPLICA );
		$row = $dbr->selectRow(
			'user_properties',
			[ 'up_user' ],
			[
				'up_property' => 'discord_id',
				'up_value' => $discordId
			],
			__METHOD__
		);

		if ( $row ) {
			return \User::newFromId( $row->up_user );
		}

		return null;
	}

	private function getRedirectUri() {
		return $this->getPageTitle()->getFullURL( [], false, PROTO_CANONICAL );
	}

	private function redirectToDiscord() {
		$clientId = $this->config->get( 'DiscordClientId' );
		$redirectUri = $this->getRedirectUri();

		// Generate state for CSRF protection
		$state = bin2hex( random_bytes( 16 ) );
		$this->getRequest()->getSession()->set( 'discord_link_state', $state );

		$url = "https://discord.com/api/oauth2/authorize?" . http_build_query( [
			'client_id' => $clientId,
			'redirect_uri' => $redirectUri,
			'response_type' => 'code',
			'scope' => 'identify guilds.members.read',
			'state' => $state
		] );

		$this->getOutput()->redirect( $url );
	}

	private function getGuildMember( $accessToken, $guildId ) {
		$url = "https://discord.com/api/users/@me/guilds/$guildId/member";
		$options = [
			'method' => 'GET',
		];

		$request = $this->httpRequestFactory->create( $url, $options );
		$request->setHeader( 'Authorization', 'Bearer ' . $accessToken );
		$status = $request->execute();

		if ( !$status->isOK() ) {
			return null;
		}

		return json_decode( $request->getContent(), true );
	}

	/**
	 * Synchronize MediaWiki user groups based on Discord roles
	 *
	 * @param \User $user MediaWiki user object
	 * @param array $discordRoles Array of Discord role IDs the user has
	 * @return void
	 */
	private function syncUserGroups( $user, array $discordRoles ): void {
		// Use $GLOBALS to avoid JSON parsing issues with large Discord IDs
		$roleToGroupMapping = $GLOBALS['wgDiscordRoleToGroupMapping'] ?? [];

		// If no mapping configured, skip synchronization
		if ( empty( $roleToGroupMapping ) ) {
			return;
		}

		// Debug logging
		wfDebugLog( 'DiscordAuth', sprintf(
			'[LinkDiscord] Syncing groups for user %s with Discord roles: %s',
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
					'[LinkDiscord] Role %s maps to groups: %s',
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
					'[LinkDiscord] Role %s not found in mapping',
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
			'[LinkDiscord] Current groups: %s, Target groups: %s, Managed groups: %s',
			implode( ', ', $currentGroups ),
			implode( ', ', $targetGroups ),
			implode( ', ', $managedGroups )
		) );

		// Add missing groups
		foreach ( $targetGroups as $group ) {
			if ( !in_array( $group, $currentGroups ) ) {
				wfDebugLog( 'DiscordAuth', sprintf( '[LinkDiscord] Adding user %s to group: %s', $user->getName(), $group ) );
				$this->userGroupManager->addUserToGroup( $user, $group );
			}
		}

		// Remove groups that are managed but user no longer qualifies for
		foreach ( $managedGroups as $group ) {
			if ( in_array( $group, $currentGroups ) && !in_array( $group, $targetGroups ) ) {
				wfDebugLog( 'DiscordAuth', sprintf( '[LinkDiscord] Removing user %s from group: %s', $user->getName(), $group ) );
				$this->userGroupManager->removeUserFromGroup( $user, $group );
			}
		}
	}
}
