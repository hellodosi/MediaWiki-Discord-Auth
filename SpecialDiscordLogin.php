<?php

namespace DiscordAuth;

use MediaWiki\SpecialPage\SpecialPage;
use MediaWiki\Config\Config;
use MediaWiki\Http\HttpRequestFactory;
use MediaWiki\User\UserOptionsManager;
use MediaWiki\User\UserFactory;
use Wikimedia\Rdbms\IConnectionProvider;

class SpecialDiscordLogin extends SpecialPage {

    /** @var Config */
    private $config;

    /** @var HttpRequestFactory */
    private $httpRequestFactory;

    /** @var UserOptionsManager */
    private $userOptionsManager;

    /** @var UserFactory */
    private $userFactory;

    /** @var IConnectionProvider */
    private $dbProvider;

    public function __construct(
        Config $config,
        HttpRequestFactory $httpRequestFactory,
        UserOptionsManager $userOptionsManager,
        UserFactory $userFactory,
        IConnectionProvider $dbProvider
    ) {
        parent::__construct( 'DiscordLogin' );
        $this->config = $config;
        $this->httpRequestFactory = $httpRequestFactory;
        $this->userOptionsManager = $userOptionsManager;
        $this->userFactory = $userFactory;
        $this->dbProvider = $dbProvider;
    }

    public function execute( $par ) {
        $request = $this->getRequest();
        $output = $this->getOutput();
        $this->setHeaders();

        // Check if username form was submitted
        $submittedUsername = $request->getVal( 'wpUsername' );
        if ( $request->wasPosted() && $submittedUsername ) {
            $this->handleUsernameSubmission( $submittedUsername );
            return;
        }

        // Check if we're returning from Discord
        $code = $request->getVal( 'code' );
        $state = $request->getVal( 'state' );
        $error = $request->getVal( 'error' );

        if ( $error ) {
            $output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-oauth', $error )->escaped() . '</div>' );
            return;
        }

        if ( $code ) {
            $this->handleCallback( $code, $state );
            return;
        }

        // Redirect to Discord OAuth
        $this->redirectToDiscord();
    }

    private function redirectToDiscord() {
        $clientId = $this->config->get( 'DiscordClientId' );
        $redirectUri = $this->getRedirectUri();

        // Generate state for CSRF protection
        $state = bin2hex( random_bytes( 16 ) );
        $this->getRequest()->getSession()->set( 'discord_auth_state', $state );

        $url = "https://discord.com/api/oauth2/authorize?" . http_build_query( [
                'client_id' => $clientId,
                'redirect_uri' => $redirectUri,
                'response_type' => 'code',
                'scope' => 'identify guilds.members.read',
                'state' => $state
            ] );

        $this->getOutput()->redirect( $url );
    }

    private function handleCallback( $code, $state ) {
        $output = $this->getOutput();
        $request = $this->getRequest();
        $session = $request->getSession();

        // Verify state
        $sessionState = $session->get( 'discord_auth_state' );
        if ( !$state || $state !== $sessionState ) {
            $output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-invalid-state' )->escaped() . '</div>' );
            return;
        }

        // Clear state
        $session->remove( 'discord_auth_state' );

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

        // DEBUG: Log Discord user data
        wfDebugLog( 'DiscordAuth', 'Discord User Data: ' . json_encode( $discordUser ) );

        // Check server membership and roles
        $guildId = $this->config->get( 'DiscordGuildId' );
        $allowedRoles = $this->config->get( 'DiscordAllowedRoles' );

        $memberData = $this->getGuildMember( $accessToken, $guildId );
        if ( !$memberData ) {
            $output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-not-member' )->escaped() . '</div>' );
            return;
        }

        $hasRole = false;
        if ( empty( $allowedRoles ) ) {
            $hasRole = true;
        } else {
            $userRoles = $memberData['roles'] ?? [];
            foreach ( $allowedRoles as $roleId ) {
                if ( in_array( $roleId, $userRoles ) ) {
                    $hasRole = true;
                    break;
                }
            }
        }

        if ( !$hasRole ) {
            $output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-no-role' )->escaped() . '</div>' );
            return;
        }

        // Check if user already exists by Discord ID
        $discordId = $discordUser['id'];
        $user = $this->getUserByDiscordId( $discordId );

        if ( !$user ) {
            // User doesn't exist, show username selection form
            if ( $this->config->get( 'DiscordAutoCreate' ) ) {
                $this->showUsernameSelection( $discordUser, $discordId, $memberData );
                return;
            } else {
                $output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-no-account' )->escaped() . '</div>' );
                return;
            }
        }

        // Log the user in
        $session->setUser( $user );
        $user->setCookies();
        $user->saveSettings();

        // Set Discord authentication timestamp for session timeout
        $session->set( 'discord_last_auth', time() );
        $session->save();

        // Redirect to main page
        $returnTo = $request->getVal( 'returnto' );
        if ( $returnTo ) {
            $title = \Title::newFromText( $returnTo );
        } else {
            $title = \Title::newMainPage();
        }

        $output->redirect( $title->getFullURL() );
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

    private function getRedirectUri() {
        return $this->getPageTitle()->getFullURL( [], false, PROTO_CANONICAL );
    }

    private function getWikiUsername( $discordUser ) {
        // Discord removed discriminators for most users
        $username = $discordUser['username'] ?? '';

        // Fallback if username is empty
        if ( empty( $username ) ) {
            $username = $discordUser['global_name'] ?? '';
            // Remove spaces from global_name as MediaWiki doesn't allow spaces in usernames
            $username = str_replace( ' ', '_', $username );
        }

        // Final fallback if still empty
        if ( empty( $username ) ) {
            $username = 'DiscordUser' . rand( 1000, 9999 );
        }

        // Add discriminator if present (replace # with underscore for MediaWiki compatibility)
        if ( isset( $discordUser['discriminator'] ) && $discordUser['discriminator'] !== '0' && $discordUser['discriminator'] !== '' ) {
            $username .= '_' . $discordUser['discriminator'];
        }

        // Remove invalid characters for MediaWiki usernames
        $username = preg_replace( '/[^A-Za-z0-9_\-äöüÄÖÜß]/', '_', $username );

        // Capitalize first letter to comply with MediaWiki $wgCapitalLinks = true
        $username = $this->normalizeUsername( $username );

        return $username;
    }

    private function normalizeUsername( $username ) {
        // Ensure we have a valid string
        if ( empty( $username ) || !is_string( $username ) ) {
            return '';
        }

        // MediaWiki's Title::capitalize() respects $wgCapitalLinks and handles multibyte characters correctly
        // We use mb_strtoupper to ensure proper UTF-8 handling for international characters
        if ( mb_strlen( $username ) > 0 ) {
            $username = mb_strtoupper( mb_substr( $username, 0, 1 ) ) . mb_substr( $username, 1 );
        }
        return $username;
    }

    private function getUserByDiscordId( $discordId ) {
        $dbr = $this->dbProvider->getReplicaDatabase();
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
            return $this->userFactory->newFromId( $row->up_user );
        }

        return null;
    }

    private function handleUsernameSubmission( $submittedUsername ) {
        $request = $this->getRequest();
        $session = $request->getSession();

        // Retrieve data from session
        $discordUser = $session->get( 'discord_pending_user' );
        $discordId = $session->get( 'discord_pending_id' );
        $memberData = $session->get( 'discord_pending_member' );

        // DEBUG: Log retrieved session data
        wfDebugLog( 'DiscordAuth', 'Retrieved from session - Discord User: ' . json_encode( $discordUser ) . ' | Submitted username: ' . $submittedUsername );

        if ( $discordUser && $discordId ) {
            // Clear session data
            $session->remove( 'discord_pending_user' );
            $session->remove( 'discord_pending_id' );
            $session->remove( 'discord_pending_member' );

            $this->createUserWithUsername( $submittedUsername, $discordUser, $discordId, $memberData );
        } else {
            // No pending Discord data, redirect to start
            $this->redirectToDiscord();
        }
    }

    private function showUsernameSelection( $discordUser, $discordId, $memberData = null ) {
        $request = $this->getRequest();
        $output = $this->getOutput();
        $session = $request->getSession();

        // Store data in session for form submission
        $session->set( 'discord_pending_user', $discordUser );
        $session->set( 'discord_pending_id', $discordId );
        $session->set( 'discord_pending_member', $memberData );
        $session->save();

        // Show form
        $suggestedUsername = $this->getWikiUsername( $discordUser );
        $discordUsername = htmlspecialchars( $discordUser['username'] ?? $discordUser['global_name'] ?? 'Discord User' );

        // DEBUG: Log suggested username
        wfDebugLog( 'DiscordAuth', 'Suggested username: ' . $suggestedUsername . ' | Raw Discord data: ' . json_encode( $discordUser ) );

        $output->setPageTitleMsg( $this->msg( 'discordauth-username-selection-title' ) );
        $output->addHTML( '
			<div style="max-width: 500px; margin: 50px auto; padding: 30px; background: #f8f9fa; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
				<h2 style="margin-top: 0; color: #5865F2;">' . $this->msg( 'discordauth-username-selection-header' )->escaped() . '</h2>
				<p>' . $this->msg( 'discordauth-username-selection-text', $discordUsername )->parse() . '</p>

				<form method="post" action="' . $this->getPageTitle()->getLocalURL() . '">
					<div style="margin: 20px 0;">
						<label for="wpUsername" style="display: block; margin-bottom: 5px; font-weight: bold;">
							' . $this->msg( 'discordauth-username-label' )->escaped() . '
						</label>
						<input type="text"
							   name="wpUsername"
							   id="wpUsername"
							   value="' . htmlspecialchars( $suggestedUsername ) . '"
							   required
							   pattern="[A-Za-z0-9_äöüÄÖÜß\-]+"
							   style="width: 100%; padding: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 5px; box-sizing: border-box;">
						<small style="color: #666; display: block; margin-top: 5px;">
							' . $this->msg( 'discordauth-username-hint' )->escaped() . '
						</small>
					</div>

					<button type="submit"
							style="width: 100%;
								   background: #5865F2;
								   color: white;
								   padding: 12px;
								   border: none;
								   border-radius: 5px;
								   font-size: 16px;
								   font-weight: bold;
								   cursor: pointer;">
						' . $this->msg( 'discordauth-username-submit' )->escaped() . '
					</button>
				</form>
			</div>
		' );
    }

    private function createUserWithUsername( $username, $discordUser, $discordId, $memberData = null ) {
        $output = $this->getOutput();
        $request = $this->getRequest();
        $session = $request->getSession();

        // Normalize and validate username
        $username = $this->normalizeUsername( trim( $username ) );

        // Ensure username is not empty after normalization
        if ( empty( $username ) ) {
            $output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-invalid-username' )->escaped() . '</div>' );
            $this->showUsernameSelection( $discordUser, $discordId );
            return;
        }

        // DEBUG: Log username before creation
        wfDebugLog( 'DiscordAuth', 'Creating user with username: ' . $username );

        // Validate username format first
        $testUser = $this->userFactory->newFromName( $username, UserFactory::RIGOR_CREATABLE );
        if ( !$testUser ) {
            wfDebugLog( 'DiscordAuth', 'Username validation failed for: ' . $username );
            $output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-invalid-username' )->escaped() . '</div>' );
            $this->showUsernameSelection( $discordUser, $discordId );
            return;
        }

        // Check if username already exists
        if ( $testUser->isRegistered() ) {
            wfDebugLog( 'DiscordAuth', 'Username already exists: ' . $username );
            $output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-username-exists' )->escaped() . '</div>' );
            $this->showUsernameSelection( $discordUser, $discordId );
            return;
        }

        // Create user using User::createNew which is more reliable
        $user = \User::createNew( $username, [
            'email' => $discordUser['email'] ?? '',
            'real_name' => $discordUser['global_name'] ?? '',
        ] );

        if ( !$user ) {
            wfDebugLog( 'DiscordAuth', 'Failed to create user with User::createNew' );
            $output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-create-failed' )->escaped() . '</div>' );
            return;
        }

        // DEBUG: Verify user was created
        wfDebugLog( 'DiscordAuth', 'User created with ID: ' . $user->getId() . ' and name: ' . $user->getName() );

        // Confirm email if provided
        if ( isset( $discordUser['email'] ) && $discordUser['email'] ) {
            $user->confirmEmail();
        }

        // Store Discord ID in user_properties table
        $dbw = $this->dbProvider->getPrimaryDatabase();
        $dbw->insert(
            'user_properties',
            [
                'up_user' => $user->getId(),
                'up_property' => 'discord_id',
                'up_value' => $discordId
            ],
            __METHOD__,
            [ 'IGNORE' ]
        );

        // Save all changes to database
        $user->saveSettings();

        // Log the user in
        $session->setUser( $user );
        $user->setCookies();

        // Set Discord authentication timestamp for session timeout
        $session->set( 'discord_last_auth', time() );
        $session->save();

        // Redirect to main page
        $returnTo = $request->getVal( 'returnto' );
        if ( $returnTo ) {
            $title = \Title::newFromText( $returnTo );
        } else {
            $title = \Title::newMainPage();
        }

        $output->redirect( $title->getFullURL() );
    }
}
