-- Links between wiki accounts and Discord accounts (DiscordAuth extension)
CREATE TABLE /*_*/discordauth_links (
  -- user.user_id of the wiki account
  dal_user INT UNSIGNED NOT NULL,
  -- Discord user ID (snowflake)
  dal_discord_id VARBINARY(32) NOT NULL,
  -- Discord username at the time of the last login/link
  dal_discord_username VARBINARY(255) NOT NULL DEFAULT '',
  -- Timestamp of the first link
  dal_linked_at BINARY(14) NOT NULL,
  -- Timestamp of the last change
  dal_updated_at BINARY(14) NOT NULL,
  PRIMARY KEY (dal_user)
) /*$wgDBTableOptions*/;

CREATE UNIQUE INDEX /*i*/dal_discord_id ON /*_*/discordauth_links (dal_discord_id);
