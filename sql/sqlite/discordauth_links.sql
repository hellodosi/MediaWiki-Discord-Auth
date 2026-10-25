-- Links between wiki accounts and Discord accounts (DiscordAuth extension)
CREATE TABLE /*_*/discordauth_links (
  dal_user INTEGER UNSIGNED NOT NULL,
  dal_discord_id BLOB NOT NULL,
  dal_discord_username BLOB DEFAULT '' NOT NULL,
  dal_linked_at BLOB NOT NULL,
  dal_updated_at BLOB NOT NULL,
  PRIMARY KEY(dal_user)
);

CREATE UNIQUE INDEX dal_discord_id ON /*_*/discordauth_links (dal_discord_id);
