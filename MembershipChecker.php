<?php

namespace DiscordAuth;

use MediaWiki\Config\Config;
use MediaWiki\User\UserGroupManager;

/**
 * Handles periodic Discord membership checks and user group management
 */
class MembershipChecker {

	/** @var Config */
	private $config;

	/** @var UserGroupManager */
	private $userGroupManager;

	/** @var DiscordLinkStore */
	private $linkStore;

	public function __construct(
		Config $config,
		UserGroupManager $userGroupManager,
		?DiscordLinkStore $linkStore = null
	) {
		$this->config = $config;
		$this->userGroupManager = $userGroupManager;
		$this->linkStore = $linkStore ?? DiscordLinkStore::getInstance();
	}

	/**
	 * Check if user should be blocked based on Discord membership
	 */
	public function shouldBlockUser( $user ): bool {
		// Only enforce if enabled
		if ( !$this->config->get( 'DiscordEnforceMembership' ) ) {
			return false;
		}

		// Check if user has Discord linked
		$discordId = $this->linkStore->getDiscordId( $user );
		if ( !$discordId ) {
			// User doesn't have Discord linked, don't block
			return false;
		}

		// Check if user is in the "discord-verified" group
		$groups = $this->userGroupManager->getUserGroups( $user );
		if ( !in_array( 'discord-verified', $groups ) ) {
			// User is not verified, should be blocked
			return true;
		}

		return false;
	}

	/**
	 * Add user to discord-verified group
	 */
	public function verifyUser( $user ): void {
		$this->userGroupManager->addUserToGroup( $user, 'discord-verified' );
	}

	/**
	 * Remove user from discord-verified group
	 */
	public function unverifyUser( $user ): void {
		$this->userGroupManager->removeUserFromGroup( $user, 'discord-verified' );
	}
}
