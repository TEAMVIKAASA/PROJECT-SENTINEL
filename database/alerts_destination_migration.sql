-- Run this once in the Supabase SQL editor.
-- Existing alerts remain valid; new detections will record the packet destination.
ALTER TABLE alerts
ADD COLUMN IF NOT EXISTS destination_ip text;
