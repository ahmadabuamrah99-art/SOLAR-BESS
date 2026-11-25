// Public browser configuration for GreenGrid.
//
// These two values are NOT secrets, but they must be correct before the app runs:
//   * SUPABASE_URL: the project URL, e.g. https://abcdefghijklmnop.supabase.co
//   * SUPABASE_ANON_KEY: the PUBLISHABLE (or legacy "anon") key from
//     Supabase Dashboard -> Project Settings -> API Keys.
//
// NEVER put the service_role key (or any sb_secret_ key) in this file.
// The app refuses to start if it detects one.
//
// Security does not depend on hiding this key. Row Level Security in the
// database decides what each signed-in user can read and write.

export const SUPABASE_URL = "https://zxmxjsfeboalahjslgcl.supabase.co";
export const SUPABASE_ANON_KEY = "sb_publishable_8wqdn499bNmxT7RcWsJzbA_wqFa32At";
