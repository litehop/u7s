# Internal: source this, don't run it directly.
#
# Loads install.sh's own manifest renderers (render_vendored_manifests,
# render_flannel and the CIDR/MTU helpers they call), so the dev rig and CI
# render manifests/*.yaml with the very functions the installer uses (install.sh
# is shipped standalone and cannot source a library).
_flannel_render_install_sh="$(dirname "${BASH_SOURCE[0]}")/../install.sh"
for _flannel_render_fn in ipv4_to_int int_to_ipv4 ip6_to_hex ip6_hex_to_str ip6_mask_hex \
  ip6_prefix_equal ip6_add_hex parse_cidr default_cluster_dns derive_pod_mtu render_flannel \
  render_vendored_manifests; do
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

# Stages every <src>/*.yaml into <dst> (replacing whatever *.yaml it held) and
# renders them in place with install.sh's render_vendored_manifests, which reads
# the globals install.sh sets: IFACE, IFACE_IP, KUBE_VERSION, POD_MTU, CLUSTER_DNS,
# POD_CLUSTER_CIDR[_IPV4|_IPV6], SERVICE_CIDR[_IPV4|_IPV6]. The glob is the same
# one install.sh uses, so a newly shipped manifest is staged without any edit here.
stage_vendored_manifests() {
  local src="$1" dst="$2" f
  mkdir -p "$dst"
  find "$dst" -maxdepth 1 -name '*.yaml' -delete
  for f in "$src"/*.yaml; do
    [ -e "$f" ] || continue
    cp "$f" "$dst/"
  done
  render_vendored_manifests "$dst"
}
