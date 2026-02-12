-- Add profile_picture column to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture VARCHAR(255);

-- Add bio column for user status/bio
ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;
