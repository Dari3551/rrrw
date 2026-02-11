export const DEFAULT_PERMS = {
  view_channel: true,
  send_messages: true,
  manage_channels: false,
  manage_roles: false,
  manage_server: false,
  admin: false,
  connect_voice: true
};

export function hasPerm(rolePerms, perm) {
  if (rolePerms?.admin) return true;
  return !!rolePerms?.[perm];
}
