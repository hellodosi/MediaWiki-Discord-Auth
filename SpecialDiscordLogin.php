<?php

namespace DiscordAuth;

use MediaWiki\SpecialPage\SpecialPage;
use MediaWiki\Config\Config;
use MediaWiki\Http\HttpRequestFactory;
use MediaWiki\User\UserOptionsManager;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserGroupManager;
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

    /** @var UserGroupManager */
    private $userGroupManager;

    public function __construct(
        Config $config,
        HttpRequestFactory $httpRequestFactory,
        UserOptionsManager $userOptionsManager,
        UserFactory $userFactory,
        IConnectionProvider $dbProvider,
        UserGroupManager $userGroupManager
    ) {
        parent::__construct( 'DiscordLogin' );
        $this->config = $config;
        $this->httpRequestFactory = $httpRequestFactory;
        $this->userOptionsManager = $userOptionsManager;
        $this->userFactory = $userFactory;
        $this->dbProvider = $dbProvider;
        $this->userGroupManager = $userGroupManager;
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
        wfDebugLog( 'DiscordAuth', 'Guild Member Data: ' . json_encode( $memberData ) );

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

        // Update discord_username if not set or outdated
        $this->userOptionsManager->setOption( $user, 'discord_username', $discordUser['username'] ?? '' );

        // Synchronize user groups based on Discord roles
        $syncMode = $this->config->get( 'DiscordGroupSyncMode' );
        wfDebugLog( 'DiscordAuth', sprintf(
            '[SpecialDiscordLogin] Sync mode: %s, Will sync: %s',
            $syncMode,
            ( $syncMode === 'always' ) ? 'YES' : 'NO'
        ) );

        if ( $syncMode === 'always' ) {
            $userRoles = $memberData['roles'] ?? [];
            $this->syncUserGroups( $user, $userRoles );
        }

        // Log the user in
        $session->setUser( $user );

        // Set remember me to true to ensure cookies last long enough
        $session->setRememberUser( true );

        // Set Discord authentication timestamp for session timeout
        $session->set( 'discord_last_auth', time() );
        $session->save();

        // Set cookies with extended expiration (1 week minimum)
        $user->setCookies( null, null, true );

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
        }

        // Final fallback if still empty
        if ( empty( $username ) ) {
            $username = 'DiscordUser' . $discordUser['id'];
        }

        // Remove or replace invalid characters per MediaWiki rules
        // Invalid: #, <, >, [, ], |, {, }, %, :, /, control chars (0x00-0x1F, 0x7F)
        $username = preg_replace( '/[#<>\[\]|{}%:\/\x00-\x1F\x7F]/', '', $username );

        // Trim whitespace
        $username = trim( $username );

        // Collapse multiple spaces/underscores to single space
        $username = preg_replace( '/[\s_]+/', ' ', $username );

        // Remove trailing spaces and underscores BEFORE canonicalization
        $username = rtrim( $username, " _\t\n\r\0\x0B" );

        // Ensure username is not empty after sanitization
        if ( $username === '' ) {
            $username = 'DiscordUser' . $discordUser['id'];
        }

        // Use MediaWiki's User::newFromName() with RIGOR_CREATABLE for validation
        // This is more compatible across MediaWiki versions
        $testUser = $this->userFactory->newFromName( $username, \MediaWiki\User\UserFactory::RIGOR_CREATABLE );

        if ( !$testUser ) {
            // If validation fails, use Discord ID as fallback
            $username = 'DiscordUser' . $discordUser['id'];
            $testUser = $this->userFactory->newFromName( $username, \MediaWiki\User\UserFactory::RIGOR_CREATABLE );
        }

        // Get the canonical name from the User object
        $canonicalName = $testUser ? $testUser->getName() : $username;

        // CRITICAL: Remove trailing underscores AFTER canonicalization
        // MediaWiki converts spaces to underscores
        $canonicalName = rtrim( $canonicalName, '_' );

        // Final validation: ensure the cleaned name is still valid
        $finalUser = $this->userFactory->newFromName( $canonicalName, \MediaWiki\User\UserFactory::RIGOR_CREATABLE );
        if ( !$finalUser || $canonicalName === '' ) {
            // If still invalid, use Discord ID as ultimate fallback
            $canonicalName = 'DiscordUser' . $discordUser['id'];
            $finalUser = $this->userFactory->newFromName( $canonicalName, \MediaWiki\User\UserFactory::RIGOR_CREATABLE );
            $canonicalName = $finalUser ? $finalUser->getName() : $canonicalName;
        }

        return $canonicalName;
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

        // Show form with pre-sanitized username suggestion
        $suggestedUsername = $this->getWikiUsername( $discordUser );
        $discordUsername = htmlspecialchars( $discordUser['username'] ?? $discordUser['global_name'] ?? 'Discord User' );

        // DEBUG: Log suggested username
        wfDebugLog( 'DiscordAuth', 'Suggested username: ' . $suggestedUsername . ' | Raw Discord data: ' . json_encode( $discordUser ) );

        $output->setPageTitleMsg( $this->msg( 'discordauth-username-selection-title' ) );
        $output->addHTML( '
			<div style="max-width: 500px; margin: 50px auto; padding: 30px; background: #f8f9fa; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
				<h2 style="margin-top: 0; color: #5865F2;">' . $this->msg( 'discordauth-username-selection-header' )->escaped() . '</h2>
				<p>' . $this->msg( 'discordauth-username-selection-text', $discordUsername )->parse() . '</p>

				<form method="post" action="' . $this->getPageTitle()->getLocalURL() . '" id="usernameForm">
					<div style="margin: 20px 0;">
						<label for="wpUsername" style="display: block; margin-bottom: 5px; font-weight: bold;">
							' . $this->msg( 'discordauth-username-label' )->escaped() . '
						</label>
						<input type="text"
							   name="wpUsername"
							   id="wpUsername"
							   value="' . htmlspecialchars( $suggestedUsername ) . '"
							   required
							   style="width: 100%; padding: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 5px; box-sizing: border-box;">
						<small style="color: #666; display: block; margin-top: 5px;">
							<strong>Erlaubt:</strong> Buchstaben, Zahlen, Unterstriche (nicht am Ende)<br>
							<strong>Verboten:</strong> Sonderzeichen wie #, &lt;, &gt;, [, ], |, {, }, %, :, /<br>
							<strong>Hinweis:</strong> Leerzeichen werden automatisch in Unterstriche umgewandelt
						</small>
						<div id="usernameError" style="color: #dc3545; margin-top: 5px; display: none; font-weight: bold;"></div>
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

			<script>
			(function() {
				var input = document.getElementById("wpUsername");
				var errorDiv = document.getElementById("usernameError");
				var form = document.getElementById("usernameForm");

				function validateUsername(username) {
					var errors = [];

					// Check for forbidden characters
					if (/[#<>\[\]|{}%:\/\x00-\x1F\x7F]/.test(username)) {
						errors.push("Verbotene Sonderzeichen enthalten (#, <, >, [, ], |, {, }, %, :, /)");
					}

					// Check for trailing underscores
					if (/_$/.test(username)) {
						errors.push("Darf nicht auf Unterstrich enden");
					}

					// Check if empty
					if (username.trim() === "") {
						errors.push("Benutzername darf nicht leer sein");
					}

					// Check length (MediaWiki max is 255 bytes)
					if (new Blob([username]).size > 255) {
						errors.push("Benutzername zu lang (max. 255 Bytes)");
					}

					return errors;
				}

				function showErrors(errors) {
					if (errors.length > 0) {
						errorDiv.innerHTML = "⚠️ " + errors.join("<br>⚠️ ");
						errorDiv.style.display = "block";
						input.style.borderColor = "#dc3545";
						return false;
					} else {
						errorDiv.style.display = "none";
						input.style.borderColor = "#28a745";
						return true;
					}
				}

				// Real-time validation
				input.addEventListener("input", function() {
					var errors = validateUsername(input.value);
					showErrors(errors);
				});

				// Form submission validation
				form.addEventListener("submit", function(e) {
					var errors = validateUsername(input.value);
					if (!showErrors(errors)) {
						e.preventDefault();
						return false;
					}
				});

				// Initial validation
				var initialErrors = validateUsername(input.value);
				showErrors(initialErrors);
			})();
			</script>
		' );
    }

    private function createUserWithUsername( $username, $discordUser, $discordId, $memberData = null ) {
        $output = $this->getOutput();
        $request = $this->getRequest();
        $session = $request->getSession();

        // Trim input
        $originalUsername = trim( $username );
        $username = $originalUsername;

        // Validate against forbidden characters before sanitization
        $validationErrors = [];

        if ( preg_match( '/[#<>\[\]|{}%:\/\x00-\x1F\x7F]/', $username ) ) {
            $validationErrors[] = 'Der Benutzername enthält verbotene Sonderzeichen (#, &lt;, &gt;, [, ], |, {, }, %, :, /)';
        }

        if ( preg_match( '/_$/', $username ) ) {
            $validationErrors[] = 'Der Benutzername darf nicht auf einem Unterstrich enden';
        }

        if ( strlen( $username ) === 0 ) {
            $validationErrors[] = 'Der Benutzername darf nicht leer sein';
        }

        if ( strlen( $username ) > 255 ) {
            $validationErrors[] = 'Der Benutzername ist zu lang (maximal 255 Zeichen)';
        }

        // Show specific validation errors
        if ( !empty( $validationErrors ) ) {
            wfDebugLog( 'DiscordAuth', 'Username validation failed for: ' . $username . ' - Errors: ' . implode( ', ', $validationErrors ) );
            $errorHtml = '<div class="error" style="padding: 15px; background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 5px; color: #721c24; margin: 20px auto; max-width: 500px;">';
            $errorHtml .= '<strong>⚠️ Ungültiger Benutzername:</strong><ul style="margin: 10px 0; padding-left: 20px;">';
            foreach ( $validationErrors as $error ) {
                $errorHtml .= '<li>' . htmlspecialchars( $error ) . '</li>';
            }
            $errorHtml .= '</ul></div>';
            $output->addHTML( $errorHtml );
            $this->showUsernameSelection( $discordUser, $discordId, $memberData );
            return;
        }

        // Apply same strict sanitization as getWikiUsername()
        // Remove or replace invalid characters per MediaWiki rules
        $username = preg_replace( '/[#<>\[\]|{}%:\/\x00-\x1F\x7F]/', '', $username );
        $username = trim( $username );
        $username = preg_replace( '/[\s_]+/', ' ', $username );
        $username = rtrim( $username, " _\t\n\r\0\x0B" );

        // Ensure username is not empty after sanitization
        if ( $username === '' ) {
            $output->addHTML( '<div class="error" style="padding: 15px; background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 5px; color: #721c24; margin: 20px auto; max-width: 500px;">Der Benutzername ist nach der Bereinigung leer.</div>' );
            $this->showUsernameSelection( $discordUser, $discordId, $memberData );
            return;
        }

        // Use MediaWiki's User::newFromName() with RIGOR_CREATABLE for validation
        $testUser = $this->userFactory->newFromName( $username, \MediaWiki\User\UserFactory::RIGOR_CREATABLE );

        if ( !$testUser ) {
            wfDebugLog( 'DiscordAuth', 'Username validation failed for: ' . $username );
            $output->addHTML( '<div class="error" style="padding: 15px; background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 5px; color: #721c24; margin: 20px auto; max-width: 500px;">Der Benutzername entspricht nicht den MediaWiki-Richtlinien (z.B. IP-Adresse oder reservierter Name).</div>' );
            $this->showUsernameSelection( $discordUser, $discordId, $memberData );
            return;
        }

        // Get the canonical name from the User object
        $canonicalName = $testUser->getName();

        // CRITICAL: Remove trailing underscores AFTER canonicalization
        $canonicalName = rtrim( $canonicalName, '_' );

        // Final validation after removing trailing underscores
        $finalUser = $this->userFactory->newFromName( $canonicalName, \MediaWiki\User\UserFactory::RIGOR_CREATABLE );
        if ( !$finalUser || $canonicalName === '' ) {
            wfDebugLog( 'DiscordAuth', 'Username final validation failed for: ' . $canonicalName );
            $output->addHTML( '<div class="error" style="padding: 15px; background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 5px; color: #721c24; margin: 20px auto; max-width: 500px;">Der Benutzername konnte nicht validiert werden. Bitte versuchen Sie einen anderen Namen.</div>' );
            $this->showUsernameSelection( $discordUser, $discordId, $memberData );
            return;
        }

        // Use the validated final name
        $username = $canonicalName;

        // DEBUG: Log username before creation
        wfDebugLog( 'DiscordAuth', 'Creating user with username: ' . $username );

        // Validate username format first
        $testUser = $this->userFactory->newFromName( $username, UserFactory::RIGOR_CREATABLE );
        if ( !$testUser ) {
            wfDebugLog( 'DiscordAuth', 'Username validation failed for: ' . $username );
            $output->addHTML( '<div class="error">' . $this->msg( 'discordauth-error-invalid-username' )->escaped() . '</div>' );
            $this->showUsernameSelection( $discordUser, $discordId, $memberData );
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

        // Store Discord ID and username in user_properties table
        $dbw = $this->dbProvider->getPrimaryDatabase();
        $dbw->insert(
            'user_properties',
            [
                [
                    'up_user' => $user->getId(),
                    'up_property' => 'discord_id',
                    'up_value' => $discordId
                ],
                [
                    'up_user' => $user->getId(),
                    'up_property' => 'discord_username',
                    'up_value' => $discordUser['username'] ?? ''
                ]
            ],
            __METHOD__,
            [ 'IGNORE' ]
        );

        // Save all changes to database
        $user->saveSettings();

        // Synchronize user groups based on Discord roles
        $syncMode = $this->config->get( 'DiscordGroupSyncMode' );
        if ( $syncMode !== 'disabled' && $memberData ) {
            $userRoles = $memberData['roles'] ?? [];
            wfDebugLog( 'DiscordAuth', '[SpecialDiscordLogin - New User] Syncing groups with roles: ' . implode( ', ', $userRoles ) );
            $this->syncUserGroups( $user, $userRoles );
        }

        // Log the user in
        $session->setUser( $user );

        // Set remember me to true to ensure cookies last long enough
        $session->setRememberUser( true );

        // Set Discord authentication timestamp for session timeout
        $session->set( 'discord_last_auth', time() );
        $session->save();

        // Set cookies with extended expiration (1 week minimum)
        $user->setCookies( null, null, true );

        // Redirect to main page
        $returnTo = $request->getVal( 'returnto' );
        if ( $returnTo ) {
            $title = \Title::newFromText( $returnTo );
        } else {
            $title = \Title::newMainPage();
        }

        $output->redirect( $title->getFullURL() );
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
            wfDebugLog( 'DiscordAuth', '[SpecialDiscordLogin] No role mapping configured, skipping sync' );
            return;
        }

        // Convert to associative array if using new format [['role' => '...', 'group' => '...']]
        $mappingArray = $this->normalizeRoleMapping( $roleToGroupMapping );

        // Debug logging
        wfDebugLog( 'DiscordAuth', sprintf(
            '[SpecialDiscordLogin] Syncing groups for user %s with Discord roles: %s',
            $user->getName(),
            implode( ', ', $discordRoles )
        ) );

        // Determine which groups the user should have based on their Discord roles
        $targetGroups = [];
        foreach ( $discordRoles as $roleId ) {
            // Ensure roleId is a string for comparison
            $roleId = (string)$roleId;

            // Check both string and potential numeric keys
            if ( isset( $mappingArray[$roleId] ) ) {
                $groups = $mappingArray[$roleId];
                wfDebugLog( 'DiscordAuth', sprintf(
                    '[SpecialDiscordLogin] Role %s maps to groups: %s',
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
                    '[SpecialDiscordLogin] Role %s not found in mapping',
                    $roleId
                ) );
            }
        }
        $targetGroups = array_unique( $targetGroups );

        // Get all groups that are managed by the mapping (to determine which to remove)
        $managedGroups = [];
        foreach ( $mappingArray as $groups ) {
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
            '[SpecialDiscordLogin] Current groups: %s, Target groups: %s, Managed groups: %s',
            implode( ', ', $currentGroups ),
            implode( ', ', $targetGroups ),
            implode( ', ', $managedGroups )
        ) );

        // Add missing groups
        foreach ( $targetGroups as $group ) {
            if ( !in_array( $group, $currentGroups ) ) {
                wfDebugLog( 'DiscordAuth', sprintf( '[SpecialDiscordLogin] Adding user %s to group: %s', $user->getName(), $group ) );
                $this->userGroupManager->addUserToGroup( $user, $group );
            }
        }

        // Remove groups that are managed but user no longer qualifies for
        foreach ( $managedGroups as $group ) {
            if ( in_array( $group, $currentGroups ) && !in_array( $group, $targetGroups ) ) {
                wfDebugLog( 'DiscordAuth', sprintf( '[SpecialDiscordLogin] Removing user %s from group: %s', $user->getName(), $group ) );
                $this->userGroupManager->removeUserFromGroup( $user, $group );
            }
        }
    }

    /**
     * Normalize role mapping to handle both old and new formats
     * Old format (doesn't work with large IDs): ['1234567' => 'group']
     * New format: [['role' => '1234567', 'group' => 'group']]
     *
     * @param array $mapping Raw mapping configuration
     * @return array Normalized associative array [roleId => group(s)]
     */
    private function normalizeRoleMapping( array $mapping ): array {
        $normalized = [];

        // Check if this is the new format (array of arrays with 'role' and 'group' keys)
        if ( isset( $mapping[0] ) && is_array( $mapping[0] ) && isset( $mapping[0]['role'] ) ) {
            // New format: [['role' => '...', 'group' => '...']]
            foreach ( $mapping as $item ) {
                if ( isset( $item['role'] ) && isset( $item['group'] ) ) {
                    $normalized[$item['role']] = $item['group'];
                }
            }
        } else {
            // Old format (or already normalized): ['roleId' => 'group']
            $normalized = $mapping;
        }

        return $normalized;
    }
}
