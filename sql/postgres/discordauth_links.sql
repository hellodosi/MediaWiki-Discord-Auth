-- Links between wiki accounts and Discord accounts (DiscordAuth extension)
CREATE TABLE discordauth_links (
  dal_user INT NOT NULL,
  dal_discord_id TEXT NOT NULL,
  dal_discord_username TEXT DEFAULT '' NOT NULL,
  dal_linked_at TIMESTAMPTZ NOT NULL,
  dal_updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(dal_user)
);

CREATE UNIQUE INDEX dal_discord_id ON discordauth_links (dal_discord_id);
