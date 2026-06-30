<?php

namespace DiscordAuth;

use MediaWiki\SpecialPage\SpecialPage;
use MediaWiki\Config\Config;
use Wikimedia\Rdbms\IConnectionProvider;
use MediaWiki\User\UserFactory;
use MediaWiki\User\User;
use HTMLForm;
use Status;
use Title;
use WikiPage;
use ContentHandler;
use CommentStoreComment;
use MediaWiki\MediaWikiServices;

class SpecialDiscordUserMerge extends SpecialPage {

	/** @var Config */
	private $config;

	/** @var IConnectionProvider */
	private $dbProvider;

	/** @var UserFactory */
	private $userFactory;

	public function __construct(
		Config $config,
		IConnectionProvider $dbProvider,
		UserFactory $userFactory
	) {
		parent::__construct( 'DiscordUserMerge', 'block' ); // Restrict to users with 'block' right (Admins)
		$this->config = $config;
		$this->dbProvider = $dbProvider;
		$this->userFactory = $userFactory;
	}

	public function execute( $par ) {
		$this->setHeaders();
		$output = $this->getOutput();
		$request = $this->getRequest();
		$output->setPageTitle( $this->msg( 'discordauth-usermerge-title' ) );

		// Check permissions
		$this->checkPermissions();

		$sourceUserDefault = $request->getVal( 'source', $par ?? '' );

		$formDescriptor = [
			'SourceUser' => [
				'type' => 'text',
				'label-message' => 'discordauth-usermerge-source-label',
				'required' => true,
				'help-message' => 'discordauth-usermerge-source-help',
				'default' => $sourceUserDefault,
			],
			'TargetUser' => [
				'type' => 'text',
				'label-message' => 'discordauth-usermerge-target-label',
				'required' => false,
				'help-message' => 'discordauth-usermerge-target-help',
			],
			'WarningBox' => [
				'type' => 'info',
				'default' => '<div class="warningbox"><strong>' . $this->msg( 'discordauth-usermerge-warning-title' )->escaped() . '</strong><br>' . $this->msg( 'discordauth-usermerge-warning-text' )->parse() . '</div>',
				'raw' => true,
			],
			'ConfirmCheckbox' => [
				'type' => 'check',
				'label-message' => 'discordauth-usermerge-confirm-label',
				'required' => true,
			]
		];

		$htmlForm = HTMLForm::factory( 'ooui', $formDescriptor, $this->getContext() );
		$htmlForm->setSubmitTextMsg( 'discordauth-usermerge-submit' );
		$htmlForm->setSubmitCallback( [ $this, 'onSubmit' ] );
		$htmlForm->show();
	}

	public function onSubmit( array $formData ) {
		$sourceName = trim( $formData['SourceUser'] );
		$targetName = trim( $formData['TargetUser'] );

		// Validate Source User
		$sourceUser = $this->userFactory->newFromName( $sourceName );
		if ( !$sourceUser || !$sourceUser->isRegistered() ) {
			return Status::newFatal( $this->msg( 'discordauth-usermerge-error-source-not-exist' ) );
		}

		// Validate Target User if specified
		$targetUser = null;
		if ( $targetName !== '' ) {
			$targetUser = $this->userFactory->newFromName( $targetName );
			if ( !$targetUser || !$targetUser->isRegistered() ) {
				return Status::newFatal( $this->msg( 'discordauth-usermerge-error-target-not-exist' ) );
			}
			if ( $sourceUser->getId() === $targetUser->getId() ) {
				return Status::newFatal( $this->msg( 'discordauth-usermerge-error-same-user' ) );
			}
		}

		// Execute merge/deletion
		$status = $this->executeMergeOrDelete( $sourceUser, $targetUser );
		if ( $status->isOK() ) {
			$this->getOutput()->addHTML( '<div class="successbox">' . $this->msg( 'discordauth-usermerge-success' )->parse() . '</div>' );
			return true;
		} else {
			return $status;
		}
	}

	private function executeMergeOrDelete( User $sourceUser, ?User $targetUser ): Status {
		$dbw = $this->dbProvider->getPrimaryDatabase();

		$sourceUserId = $sourceUser->getId();
		$sourceActorId = $dbw->selectField(
			'actor',
			'actor_id',
			[ 'actor_user' => $sourceUserId ],
			__METHOD__
		);

		if ( $targetUser ) {
			$targetUserId = $targetUser->getId();
			$targetActorId = $dbw->selectField(
				'actor',
				'actor_id',
				[ 'actor_user' => $targetUserId ],
				__METHOD__
			);

			if ( !$targetActorId ) {
				$dbw->insert(
					'actor',
					[ 'actor_name' => $targetUser->getName(), 'actor_user' => $targetUserId ],
					__METHOD__
				);
				$targetActorId = $dbw->insertId();
			}
		} else {
			// Pure deletion: assign to "Gelöschter Benutzer"
			$targetActorId = $dbw->selectField(
				'actor',
				'actor_id',
				[ 'actor_name' => 'Gelöschter Benutzer', 'actor_user' => null ],
				__METHOD__
			);
			if ( !$targetActorId ) {
				$dbw->insert(
					'actor',
					[ 'actor_name' => 'Gelöschter Benutzer', 'actor_user' => null ],
					__METHOD__
				);
				$targetActorId = $dbw->insertId();
			}
		}

		// Start transaction
		$dbw->startAtomic( __METHOD__ );
		try {
			if ( $sourceActorId && $targetActorId ) {
				// Reattribute edits/revisions/logs
				$dbw->update( 'revision', [ 'rev_actor' => $targetActorId ], [ 'rev_actor' => $sourceActorId ], __METHOD__ );
				$dbw->update( 'archive', [ 'ar_actor' => $targetActorId ], [ 'ar_actor' => $sourceActorId ], __METHOD__ );
				$dbw->update( 'image', [ 'img_actor' => $targetActorId ], [ 'img_actor' => $sourceActorId ], __METHOD__ );
				$dbw->update( 'oldimage', [ 'oi_actor' => $targetActorId ], [ 'oi_actor' => $sourceActorId ], __METHOD__ );
				$dbw->update( 'filearchive', [ 'fa_actor' => $targetActorId ], [ 'fa_actor' => $sourceActorId ], __METHOD__ );
				$dbw->update( 'logging', [ 'log_actor' => $targetActorId ], [ 'log_actor' => $sourceActorId ], __METHOD__ );
				$dbw->update( 'recentchanges', [ 'rc_actor' => $targetActorId ], [ 'rc_actor' => $sourceActorId ], __METHOD__ );
			}

			// Delete source user record and associations
			$dbw->delete( 'user', [ 'user_id' => $sourceUserId ], __METHOD__ );
			$dbw->delete( 'user_groups', [ 'ug_user' => $sourceUserId ], __METHOD__ );
			$dbw->delete( 'user_properties', [ 'up_user' => $sourceUserId ], __METHOD__ );

			// Delete source actor row
			if ( $sourceActorId ) {
				$dbw->delete( 'actor', [ 'actor_id' => $sourceActorId ], __METHOD__ );
			}

			$dbw->endAtomic( __METHOD__ );
		} catch ( \Exception $e ) {
			$dbw->rollbackAtomic( __METHOD__ );
			return Status::newFatal( 'Datenbankfehler: ' . $e->getMessage() );
		}

		// Redirect or delete user page
		$this->handleUserPage( $sourceUser->getName(), $targetUser ? $targetUser->getName() : null );

		return Status::newGood();
	}

	private function handleUserPage( string $sourceName, ?string $targetName ) {
		$services = MediaWikiServices::getInstance();
		$sourceTitle = Title::makeTitle( NS_USER, $sourceName );
		$admin = $this->getUser();

		if ( $targetName ) {
			// Redirect to target user page
			$targetTitle = Title::makeTitle( NS_USER, $targetName );
			$wikiPage = $services->getWikiPageFactory()->newFromTitle( $sourceTitle );
			$redirectText = '#REDIRECT [[' . $targetTitle->getPrefixedText() . ']]';
			$content = ContentHandler::makeContent( $redirectText, $sourceTitle );

			if ( $wikiPage ) {
				if ( method_exists( $wikiPage, 'newPageUpdater' ) ) {
					$updater = $wikiPage->newPageUpdater( $admin );
					$updater->setContent( 'main', $content );
					$updater->saveRevision( CommentStoreComment::newUnsavedComment( 'Benutzer zusammengeführt - Weiterleitung erstellt' ) );
				} else {
					$wikiPage->doEditContent( $content, 'Benutzer zusammengeführt - Weiterleitung erstellt', 0, false, $admin );
				}
			}
		} else {
			// Delete source user page
			if ( $sourceTitle->exists() ) {
				$wikiPage = $services->getWikiPageFactory()->newFromTitle( $sourceTitle );
				if ( $wikiPage ) {
					$reason = 'Benutzer entfernt';
					if ( class_exists( '\MediaWiki\Page\DeletePage' ) ) {
						$deletePage = $services->getDeletePageFactory()->newDeletePage( $wikiPage, $admin );
						$deletePage->deleteIfAllowed( $reason );
					} else {
						$wikiPage->doDeleteArticleReal( $reason, $admin );
					}
				}
			}
		}
	}

	protected function getGroupName() {
		return 'users';
	}
}
