# Internal: source this, don't run it directly.
#
# Loads derive_pod_mtu and render_flannel from scripts/install.sh itself, so the
# dev rig and CI render manifests/flannel.yaml with the very functions the
# installer uses (install.sh is shipped standalone and cannot source a library).
_flannel_render_install_sh="$(dirname "${BASH_SOURCE[0]}")/../install.sh"
for _flannel_render_fn in derive_pod_mtu render_flannel; do
  eval "$(awk -v f="$_flannel_render_fn" '$0 == f "() {" {p=1} p {print} p && /^}$/ {exit}' "$_flannel_render_install_sh")"
done
unset _flannel_render_install_sh _flannel_render_fn

# Renders manifests/flannel.yaml (stdin to stdout) for a dev/CI node whose
# <iface> has MTU <nic mtu>. Args: <iface> <nic mtu> <v4 pod cidr> <v6 pod
# cidr, empty for single-stack>.
render_flannel_for_nic() {
  local mtu v6flag=0
  [ -z "$4" ] || v6flag=1
  mtu="$(derive_pod_mtu "$2" "$v6flag")" || return 1
  render_flannel "$1" "$3" "$4" "$mtu"
}
