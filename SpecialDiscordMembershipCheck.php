<?php

namespace DiscordAuth;

use MediaWiki\SpecialPage\SpecialPage;
use MediaWiki\Config\Config;
use MediaWiki\Http\HttpRequestFactory;
use MediaWiki\User\UserOptionsLookup;
use MediaWiki\User\UserGroupManager;
use Wikimedia\Rdbms\IConnectionProvider;

class SpecialDiscordMembershipCheck extends SpecialPage {

	/** @var Config */
	private $config;

	/** @var HttpRequestFactory */
	private $httpRequestFactory;

	/** @var UserOptionsLookup */
	private $userOptionsLookup;

	/** @var IConnectionProvider */
	private $dbProvider;

	/** @var UserGroupManager */
	private $userGroupManager;

	public function __construct(
		Config $config,
		HttpRequestFactory $httpRequestFactory,
		UserOptionsLookup $userOptionsLookup,
		IConnectionProvider $dbProvider,
		UserGroupManager $userGroupManager
	) {
		parent::__construct( 'DiscordMembershipCheck', 'block' ); // Requires 'block' permission
		$this->config = $config;
		$this->httpRequestFactory = $httpRequestFactory;
		$this->userOptionsLookup = $userOptionsLookup;
		$this->dbProvider = $dbProvider;
		$this->userGroupManager = $userGroupManager;
	}

	public function execute( $par ) {
		$this->setHeaders();
		$this->checkPermissions();

		$output = $this->getOutput();
		$request = $this->getRequest();
		$user = $this->getUser();

		// Handle AJAX checking requests
		if ( $request->getVal( 'ajax' ) ) {
			$this->handleAjaxRequest();
			return;
		}

		$output->setPageTitle( $this->msg( 'discordauth-membership-check-title' )->text() );
		$output->addModuleStyles( 'mediawiki.special' );

		// Handle block action
		if ( $request->wasPosted() && $user->matchEditToken( $request->getVal( 'token' ) ) ) {
			$userToBlock = $request->getVal( 'blockuser' );
			if ( $userToBlock ) {
				$this->blockUser( $userToBlock );
			}
		}

		// Check if bot token is configured
		$botToken = $this->config->get( 'DiscordBotToken' );
		if ( !$botToken ) {
			$output->addHTML( $this->getConfigWarning() );
			return;
		}

		$output->addHTML( $this->getIntroText() );

		// Get all users with Discord ID
		$usersWithDiscord = $this->getUsersWithDiscord();

		// Get all users without Discord ID
		$usersWithoutDiscord = $this->getUsersWithoutDiscord();

		// Fetch all guild roles once for mapping IDs to names (used in JS)
		$guildId = $this->config->get( 'DiscordGuildId' );
		$guildRoles = $this->getGuildRoles( $botToken, $guildId );
		$roleIdToName = [];
		if ( $guildRoles ) {
			foreach ( $guildRoles as $role ) {
				$roleIdToName[$role['id']] = $role['name'];
			}
		}

		// Render the initial UI layout
		$this->displayInitialUI( $usersWithDiscord, $usersWithoutDiscord, $roleIdToName );
	}

	private function handleAjaxRequest() {
		$request = $this->getRequest();
		$output = $this->getOutput();
		$output->disable(); // Prevent rendering the skin

		$response = [ 'success' => false ];

		$botToken = $this->config->get( 'DiscordBotToken' );
		if ( !$botToken ) {
			$response['error'] = 'Bot token not configured';
			echo json_encode( $response );
			return;
		}

		$userId = (int)$request->getVal( 'user_id' );
		$user = \User::newFromId( $userId );

		if ( !$user || $user->getId() === 0 ) {
			$response['error'] = 'User not found';
			echo json_encode( $response );
			return;
		}

		$discordId = $this->dbProvider->getReplicaDatabase()->selectField(
			'user_properties',
			'up_value',
			[ 'up_user' => $userId, 'up_property' => 'discord_id' ],
			__METHOD__
		);

		if ( !$discordId ) {
			$response['error'] = 'No Discord ID linked';
			echo json_encode( $response );
			return;
		}

		$guildId = $this->config->get( 'DiscordGuildId' );
		$allowedRoles = $this->config->get( 'DiscordAllowedRoles' );
		$roleToGroupMapping = $GLOBALS['wgDiscordRoleToGroupMapping'] ?? [];

		// Check if user is blocked
		$isBlocked = $user->getBlock() !== null;

		// Fetch Discord member data (returns array with status/error info)
		$memberData = $this->getGuildMemberByBot( $botToken, $guildId, $discordId );

		$hasAccess = false;
		$reason = '';
		$discordRoles = [];
		$expectedGroups = [];
		$discordUsername = $this->userOptionsLookup->getOption( $user, 'discord_username', '' );
		$hasError = false;

		if ( !$memberData || ( isset( $memberData['error'] ) && $memberData['error'] ) ) {
			$statusCode = $memberData['status'] ?? 0;
			if ( $statusCode === 404 ) {
				$reason = $this->msg( 'discordauth-check-not-member' )->text();
			} elseif ( $statusCode === 429 ) {
				$reason = 'Rate-Limit überschritten (Bitte warten...)';
			} elseif ( $statusCode === 401 || $statusCode === 403 ) {
				$reason = 'Bot-Berechtigungsfehler (Token/Guild prüfen)';
			} else {
				$reason = 'Verbindungsfehler (HTTP ' . $statusCode . ')';
			}
			$hasError = true;
		} else {
			if ( isset( $memberData['user']['username'] ) ) {
				$discordUsername = $memberData['user']['username'];
			}
			$discordRoles = $memberData['roles'] ?? [];
			$expectedGroups = $this->calculateExpectedGroups( $discordRoles, $roleToGroupMapping );

			if ( empty( $allowedRoles ) ) {
				$hasAccess = true;
			} else {
				foreach ( $allowedRoles as $roleId ) {
					if ( in_array( $roleId, $discordRoles ) ) {
						$hasAccess = true;
						break;
					}
				}
				if ( !$hasAccess ) {
					$reason = $this->msg( 'discordauth-check-no-role' )->text();
				}
			}
		}

		// Get current groups
		$currentGroups = $this->userGroupManager->getUserGroups( $user );
		$groupsMatch = empty( array_diff( $expectedGroups, $currentGroups ) ) &&
					   empty( array_diff( $currentGroups, $expectedGroups ) );

		$response = [
			'success' => true,
			'user_id' => $userId,
			'discord_id' => $discordId,
			'discord_username' => $discordUsername,
			'has_access' => $hasAccess,
			'is_error' => $hasError,
			'reason' => $reason,
			'status_code' => $memberData['status'] ?? 200,
			'is_blocked' => $isBlocked,
			'discord_roles' => $discordRoles,
			'expected_groups' => $expectedGroups,
			'current_groups' => $currentGroups,
			'groups_match' => $groupsMatch,
			'sync_mode_disabled' => $this->config->get( 'DiscordGroupSyncMode' ) === 'disabled'
		];

		header( 'Content-Type: application/json; charset=utf-8' );
		echo json_encode( $response );
	}

	private function getIntroText() {
		return '<div style="background: #f8f9fa; padding: 15px; border-left: 4px solid #0645ad; margin: 20px 0;">'
			. '<p>' . $this->msg( 'discordauth-membership-check-intro' )->parse() . '</p>'
			. '<ul>'
			. '<li>' . $this->msg( 'discordauth-membership-check-info-1' )->escaped() . '</li>'
			. '<li>' . $this->msg( 'discordauth-membership-check-info-2' )->escaped() . '</li>'
			. '<li>' . $this->msg( 'discordauth-membership-check-info-3' )->escaped() . '</li>'
			. '</ul>'
			. '</div>';
	}

	private function getConfigWarning() {
		return '<div style="background: #fef6e7; border: 1px solid #fc3; padding: 15px; border-radius: 5px; margin: 20px 0;">'
			. '<h3>⚠️ ' . $this->msg( 'discordauth-bot-token-required-title' )->escaped() . '</h3>'
			. '<p>' . $this->msg( 'discordauth-bot-token-required-text' )->parse() . '</p>'
			. '<p><strong>' . $this->msg( 'discordauth-bot-token-config' )->escaped() . '</strong></p>'
			. '<pre style="background: #f5f5f5; padding: 10px; border-radius: 3px;">$wgDiscordBotToken = \'YOUR_BOT_TOKEN_HERE\';</pre>'
			. '<p>' . $this->msg( 'discordauth-bot-token-howto' )->parse() . '</p>'
			. '</div>';
	}

	private function getUsersWithDiscord() {
		$dbr = $this->dbProvider->getReplicaDatabase();
		$res = $dbr->select(
			'user_properties',
			[ 'up_user', 'up_value' ],
			[ 'up_property' => 'discord_id' ],
			__METHOD__
		);

		$users = [];
		foreach ( $res as $row ) {
			$user = \User::newFromId( $row->up_user );
			if ( $user && $user->getId() > 0 ) {
				$users[] = [
					'user' => $user,
					'discord_id' => $row->up_value,
					'discord_username' => $this->userOptionsLookup->getOption( $user, 'discord_username', '' )
				];
			}
		}

		return $users;
	}

	private function getUsersWithoutDiscord() {
		$dbr = $this->dbProvider->getReplicaDatabase();

		$usersWithDiscord = $dbr->selectFieldValues(
			'user_properties',
			'up_user',
			[ 'up_property' => 'discord_id' ],
			__METHOD__
		);

		$conditions = [ 'user_id > 0' ];
		if ( !empty( $usersWithDiscord ) ) {
			$conditions[] = 'user_id NOT IN (' . $dbr->makeList( $usersWithDiscord ) . ')';
		}

		$res = $dbr->select(
			'user',
			[ 'user_id', 'user_name' ],
			$conditions,
			__METHOD__,
			[ 'ORDER BY' => 'user_name' ]
		);

		$users = [];
		foreach ( $res as $row ) {
			$user = \User::newFromId( $row->user_id );
			if ( $user && $user->getId() > 0 ) {
				$users[] = $user;
			}
		}

		return $users;
	}

	private function getGuildMemberByBot( $botToken, $guildId, $userId ) {
		$url = "https://discord.com/api/v10/guilds/{$guildId}/members/{$userId}";

		$options = [
			'method' => 'GET',
		];

		$request = $this->httpRequestFactory->create( $url, $options );
		$request->setHeader( 'Authorization', 'Bot ' . $botToken );
		$status = $request->execute();

		$statusCode = $request->getStatus();
		if ( !$status->isOK() ) {
			return [
				'error' => true,
				'status' => $statusCode,
				'message' => $request->getContent()
			];
		}

		$data = json_decode( $request->getContent(), true );
		if ( is_array( $data ) ) {
			$data['error'] = false;
			$data['status'] = $statusCode;
			return $data;
		}

		return [
			'error' => true,
			'status' => $statusCode,
			'message' => 'Invalid JSON response'
		];
	}

	private function getGuildRoles( $botToken, $guildId ) {
		$url = "https://discord.com/api/v10/guilds/{$guildId}/roles";

		$options = [
			'method' => 'GET',
		];

		$request = $this->httpRequestFactory->create( $url, $options );
		$request->setHeader( 'Authorization', 'Bot ' . $botToken );
		$status = $request->execute();

		if ( !$status->isOK() ) {
			return null;
		}

		return json_decode( $request->getContent(), true );
	}

	private function calculateExpectedGroups( array $discordRoles, array $roleToGroupMapping ): array {
		if ( empty( $roleToGroupMapping ) ) {
			return [];
		}

		$expectedGroups = [];
		foreach ( $discordRoles as $roleId ) {
			if ( isset( $roleToGroupMapping[$roleId] ) ) {
				$groups = $roleToGroupMapping[$roleId];
				if ( is_array( $groups ) ) {
					$expectedGroups = array_merge( $expectedGroups, $groups );
				} else {
					$expectedGroups[] = $groups;
				}
			}
		}

		return array_unique( $expectedGroups );
	}

	private function displayInitialUI( $usersWithDiscord, $usersWithoutDiscord, $roleIdToName ) {
		$output = $this->getOutput();
		$user = $this->getUser();
		$roleToGroupMapping = $GLOBALS['wgDiscordRoleToGroupMapping'] ?? [];

		// Statistics
		$output->addHTML( '<div style="display: flex; gap: 15px; margin: 20px 0;">' );
		$output->addHTML( $this->getStatBox( $this->msg( 'discordauth-stat-total' )->text(), count( $usersWithDiscord ), '#0645ad' ) );
		$output->addHTML( $this->getStatBox( $this->msg( 'discordauth-stat-valid' )->text(), '<span id="stat-valid">0</span>', '#00af89' ) );
		$output->addHTML( $this->getStatBox( $this->msg( 'discordauth-stat-invalid' )->text(), '<span id="stat-invalid">0</span>', '#d73333' ) );
		$output->addHTML( $this->getStatBox( $this->msg( 'discordauth-stat-blocked' )->text(), '<span id="stat-blocked">0</span>', '#72777d' ) );
		$output->addHTML( $this->getStatBox( $this->msg( 'discordauth-stat-no-link' )->text(), count( $usersWithoutDiscord ), '#fc3' ) );
		$output->addHTML( '</div>' );

		// Table of users being checked
		$output->addHTML( '<h2>' . $this->msg( 'discordauth-checking-users', count( $usersWithDiscord ) )->escaped() . '</h2>' );
		$html = '<table class="wikitable sortable" style="width: 100%;" id="membership-check-table">';
		$html .= '<thead><tr>';
		$html .= '<th>' . $this->msg( 'discordauth-table-wiki-user' )->escaped() . '</th>';
		$html .= '<th>' . $this->msg( 'discordauth-table-discord-user' )->escaped() . '</th>';
		$html .= '<th>' . $this->msg( 'discordauth-table-status' )->escaped() . '</th>';

		if ( !empty( $roleToGroupMapping ) ) {
			$html .= '<th>Discord Rollen</th>';
			$html .= '<th>Erwartete Gruppen</th>';
			$html .= '<th>Aktuelle Gruppen</th>';
		} else {
			$html .= '<th>' . $this->msg( 'discordauth-table-groups' )->escaped() . '</th>';
		}

		$html .= '<th>' . $this->msg( 'discordauth-table-action' )->escaped() . '</th>';
		$html .= '</tr></thead><tbody>';

		foreach ( $usersWithDiscord as $userData ) {
			$wikiUser = $userData['user'];
			$currentGroups = $this->userGroupManager->getUserGroups( $wikiUser );

			$html .= '<tr class="user-check-row" data-user-id="' . $wikiUser->getId() . '" data-user-name="' . htmlspecialchars( $wikiUser->getName() ) . '">';
			$html .= '<td><a href="' . $wikiUser->getUserPage()->getFullURL() . '">' . htmlspecialchars( $wikiUser->getName() ) . '</a></td>';
			$html .= '<td class="col-discord-user"><span class="ul-loading-spinner"></span> Lade...</td>';
			$html .= '<td class="col-status"><span class="ul-loading-spinner"></span> Prüfe...</td>';

			if ( !empty( $roleToGroupMapping ) ) {
				$html .= '<td class="col-discord-roles">-</td>';
				$html .= '<td class="col-expected-groups">-</td>';
				
				$groupsHtml = htmlspecialchars( implode( ', ', $currentGroups ) );
				$groupsHtml .= '<br><a href="' . \SpecialPage::getTitleFor( 'UserRights', $wikiUser->getName() )->getFullURL() . '" style="font-size: 0.9em;">' . $this->msg( 'discordauth-group-manage' )->text() . '</a>';
				$html .= '<td class="col-current-groups">' . $groupsHtml . '</td>';
			} else {
				$groupsHtml = htmlspecialchars( implode( ', ', $currentGroups ) );
				$groupsHtml .= '<br><a href="' . \SpecialPage::getTitleFor( 'UserRights', $wikiUser->getName() )->getFullURL() . '" style="font-size: 0.9em;">' . $this->msg( 'discordauth-group-manage' )->text() . '</a>';
				$html .= '<td class="col-current-groups">' . $groupsHtml . '</td>';
			}

			$html .= '<td class="col-action">-</td>';
			$html .= '</tr>';
		}
		$html .= '</tbody></table>';
		$output->addHTML( $html );

		// Users without Discord link
		if ( !empty( $usersWithoutDiscord ) ) {
			$output->addHTML( '<h2 style="color: #fc3;">⚠️ ' . $this->msg( 'discordauth-users-no-discord' )->escaped() . '</h2>' );
			$output->addHTML( $this->getSimpleUserTable( $usersWithoutDiscord ) );
		}

		$this->injectAjaxScript( $roleIdToName, $user->getEditToken() );
	}

	private function getStatBox( $label, $value, $color ) {
		return '<div style="flex: 1; background: white; border: 2px solid ' . $color . '; border-radius: 8px; padding: 15px; text-align: center;">'
			. '<div style="font-size: 32px; font-weight: bold; color: ' . $color . ';">' . $value . '</div>'
			. '<div style="color: #72777d; margin-top: 5px;">' . htmlspecialchars( $label ) . '</div>'
			. '</div>';
	}

	private function getSimpleUserTable( $users ) {
		$html = '<table class="wikitable sortable" style="width: 100%;">';
		$html .= '<thead><tr>';
		$html .= '<th>' . $this->msg( 'discordauth-table-wiki-user' )->escaped() . '</th>';
		$html .= '<th>' . $this->msg( 'discordauth-table-status' )->escaped() . '</th>';
		$html .= '</tr></thead><tbody>';

		foreach ( $users as $wikiUser ) {
			$html .= '<tr>';
			$html .= '<td><a href="' . $wikiUser->getUserPage()->getFullURL() . '">' . htmlspecialchars( $wikiUser->getName() ) . '</a></td>';
			$html .= '<td style="color: #fc3;">' . $this->msg( 'discordauth-status-no-link' )->escaped() . '</td>';
			$html .= '</tr>';
		}

		$html .= '</tbody></table>';

		return $html;
	}

	private function injectAjaxScript( array $roleIdToName, string $editToken ) {
		$output = $this->getOutput();
		$rolesMapJson = json_encode( $roleIdToName );
		$ajaxUrl = $this->getPageTitle()->getFullURL( [ 'ajax' => 1 ] );
		$userMergeUrl = \SpecialPage::getTitleFor( 'DiscordUserMerge' )->getFullURL();
		$blockConfirmMsg = $this->msg( 'discordauth-block-confirm', '$1' )->text();
		$blockBtnText = $this->msg( 'discordauth-block-button' )->text();

		$style = '<style>
.ul-loading-spinner {
	display: inline-block;
	width: 14px;
	height: 14px;
	border: 2px solid rgba(0,0,0,0.1);
	border-radius: 50%;
	border-top-color: #0645ad;
	animation: ul-spin 1s ease-in-out infinite;
	vertical-align: middle;
	margin-right: 5px;
}
@keyframes ul-spin {
	to { transform: rotate(360deg); }
}
.status-loading { color: #72777d; }
.status-valid { color: #00af89; font-weight: bold; }
.status-invalid { color: #d73333; font-weight: bold; }
.status-blocked { color: #72777d; font-weight: bold; }
</style>';
		$output->addHTML( $style );

		$script = '<script>
document.addEventListener("DOMContentLoaded", function() {
	const rolesMap = ' . $rolesMapJson . ';
	const ajaxUrl = ' . json_encode( $ajaxUrl ) . ';
	const userMergeUrl = ' . json_encode( $userMergeUrl ) . ';
	const editToken = ' . json_encode( $editToken ) . ';
	const blockConfirmMsg = ' . json_encode( $blockConfirmMsg ) . ';
	const blockBtnText = ' . json_encode( $blockBtnText ) . ';

	const rows = Array.from(document.querySelectorAll(".user-check-row"));
	const queue = [...rows];
	let activeRequests = 0;
	const maxConcurrent = 3;
	let lastLaunchTime = 0;
	const minLaunchDelay = 300; // 300ms delay between launching requests to respect rate limit

	let statValid = 0;
	let statInvalid = 0;
	let statBlocked = 0;

	function processQueue() {
		if (queue.length === 0) return;
		if (activeRequests >= maxConcurrent) return;

		const now = Date.now();
		const timeSinceLastLaunch = now - lastLaunchTime;

		if (timeSinceLastLaunch < minLaunchDelay) {
			// Schedule next launch to respect rate limit
			setTimeout(processQueue, minLaunchDelay - timeSinceLastLaunch);
			return;
		}

		const row = queue.shift();
		activeRequests++;
		lastLaunchTime = Date.now();
		checkUser(row);

		// Try launching the next one (will self-schedule if too soon)
		processQueue();
	}

	function checkUser(row) {
		const userId = row.getAttribute("data-user-id");
		const userName = row.getAttribute("data-user-name");

		row.querySelector(".col-status").innerHTML = "<span class=\'status-loading\'><span class=\'ul-loading-spinner\'></span> Prüfe...</span>";

		fetch(ajaxUrl + "&user_id=" + userId)
			.then(response => response.json())
			.then(data => {
				activeRequests--;
				if (data.success) {
					// Handle Rate Limits (HTTP 429) - Retry after 5 seconds
					if (data.is_error && data.status_code === 429) {
						row.querySelector(".col-status").innerHTML = "<span style=\'color: orange;\'><span class=\'ul-loading-spinner\'></span> Rate-Limit (Warteschlange)</span>";
						setTimeout(() => {
							queue.push(row);
							processQueue();
						}, 5000);
						processQueue();
						return;
					}

					// Handle other API Errors (Unauthorized / Forbidden / Network etc.)
					if (data.is_error && data.status_code !== 404) {
						row.querySelector(".col-status").innerHTML = "<span class=\'status-invalid\'>⚠️ " + (data.reason || "Fehler") + "</span>";
						row.querySelector(".col-discord-user").textContent = "-";
						processQueue();
						return;
					}

					// Update Discord Username
					row.querySelector(".col-discord-user").textContent = data.discord_username || "-";

					// Update Status Column
					const colStatus = row.querySelector(".col-status");
					if (data.is_blocked) {
						colStatus.innerHTML = "<span class=\'status-blocked\'>🚫 Gesperrt</span>";
						statBlocked++;
						document.getElementById("stat-blocked").textContent = statBlocked;
					} else if (data.has_access) {
						colStatus.innerHTML = "<span class=\'status-valid\'>✓ Aktiv</span>";
						statValid++;
						document.getElementById("stat-valid").textContent = statValid;
					} else {
						colStatus.innerHTML = "<span class=\'status-invalid\'>✗ " + (data.reason || "Kein Zugriff") + "</span>";
						statInvalid++;
						document.getElementById("stat-invalid").textContent = statInvalid;

						// Render Löschen / Zusammenführen Link Button
						const colAction = row.querySelector(".col-action");
						const mergeUrl = userMergeUrl + "/" + encodeURIComponent(userName);
						
						const link = document.createElement("a");
						link.href = mergeUrl;
						link.className = "mw-ui-button mw-ui-destructive";
						link.style = "display: inline-block; text-decoration: none; padding: 5px 12px; font-weight: bold;";
						link.textContent = "Zusammenführen / Löschen";
						
						colAction.innerHTML = "";
						colAction.appendChild(link);
					}

					// Update Discord Roles
					const colRoles = row.querySelector(".col-discord-roles");
					if (colRoles) {
						if (data.discord_roles && data.discord_roles.length > 0) {
							let rolesHtml = "<details><summary>" + data.discord_roles.length + " Rollen</summary>";
							rolesHtml += "<div style=\'font-size: 0.9em; margin-top: 5px;\'>";
							let list = [];
							data.discord_roles.forEach(roleId => {
								const name = rolesMap[roleId] || "Unbekannt";
								list.push("<strong>" + name + "</strong><br><code style=\'font-size: 0.85em; color: #72777d;\'>" + roleId + "</code>");
							});
							rolesHtml += list.join("<br><br>") + "</div></details>";
							colRoles.innerHTML = rolesHtml;
						} else {
							colRoles.innerHTML = "<span style=\'color: #72777d;\'>-</span>";
						}
					}

					// Update Expected Groups
					const colExpected = row.querySelector(".col-expected-groups");
					if (colExpected) {
						if (data.expected_groups && data.expected_groups.length > 0) {
							colExpected.innerHTML = "<strong style=\'color: #00af89;\'>" + data.expected_groups.join(", ") + "</strong>";
						} else {
							colExpected.innerHTML = "<span style=\'color: #72777d;\'>-</span>";
						}
					}

					// Update Current Groups (Sync State)
					const colCurrent = row.querySelector(".col-current-groups");
					if (colCurrent && !data.sync_mode_disabled) {
						let currentHtml = data.current_groups.join(", ");
						if (data.expected_groups && data.expected_groups.length > 0) {
							if (data.groups_match) {
								colCurrent.innerHTML = "✓ " + currentHtml + " <span style=\'color: #00af89; font-size: 0.9em;\'>(synchronisiert)</span>";
							} else {
								colCurrent.innerHTML = "⚠️ " + currentHtml + " <span style=\'color: #fc3; font-size: 0.9em;\'>(nicht synchronisiert)</span>";
							}
							colCurrent.innerHTML += "<br><a href=\'" + ajaxUrl.split("?")[0].replace("Special:DiscordMembershipCheck", "Special:UserRights") + "/" + userName + "\' style=\'font-size: 0.9em;\'>Gruppen verwalten</a>";
						}
					}
				} else {
					row.querySelector(".col-status").innerHTML = "<span class=\'status-invalid\'>Fehler</span>";
				}
				processQueue();
			})
			.catch(err => {
				activeRequests--;
				row.querySelector(".col-status").innerHTML = "<span class=\'status-invalid\'>Netzwerkfehler</span>";
				processQueue();
			});
	}

	processQueue();
});
</script>';
		$output->addHTML( $script );
	}

	private function blockUser( $username ) {
		$output = $this->getOutput();
		$performer = $this->getUser();

		$targetUser = \User::newFromName( $username );
		if ( !$targetUser || $targetUser->getId() === 0 ) {
			$output->addHTML( '<div class="error">' . $this->msg( 'discordauth-block-error-user' )->escaped() . '</div>' );
			return;
		}

		$block = new \DatabaseBlock( [
			'address' => $targetUser->getName(),
			'user' => $targetUser->getId(),
			'by' => $performer->getId(),
			'reason' => $this->msg( 'discordauth-block-reason' )->text(),
			'expiry' => 'infinity',
			'createAccount' => true,
			'enableAutoblock' => true,
			'blockEmail' => false,
		] );

		$blockStatus = $block->insert();

		if ( $blockStatus ) {
			$output->addHTML( '<div class="success" style="background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; border-radius: 5px; margin: 10px 0;">'
				. $this->msg( 'discordauth-block-success', $username )->parse()
				. '</div>' );

			$logEntry = new \ManualLogEntry( 'block', 'block' );
			$logEntry->setPerformer( $performer );
			$logEntry->setTarget( $targetUser->getUserPage() );
			$logEntry->setComment( $this->msg( 'discordauth-block-reason' )->text() );
			$logEntry->setParameters( [
				'5::duration' => 'infinite',
				'6::flags' => 'nocreate',
			] );
			$logEntry->insert();
		} else {
			$output->addHTML( '<div class="error">' . $this->msg( 'discordauth-block-error' )->escaped() . '</div>' );
		}

		$output->redirect( $this->getPageTitle()->getFullURL() );
	}

	public function doesWrites() {
		return true;
	}

	protected function getGroupName() {
		return 'users';
	}
}
