-- ArgusWatch v16.4.8 hotfix
-- Ensure customer primary domain exists for ORM queries
ALTER TABLE customers ADD COLUMN IF NOT EXISTS primary_domain VARCHAR(255);
