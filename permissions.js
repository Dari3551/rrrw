export const DEFAULT_PERMS = {
  view_channels: true,
  send_messages: true,
  join_voice: true,
};

export function hasPerm(perms, key) {
  if (!perms) return false;
  if (perms.admin) return true;
  return !!perms[key];
}