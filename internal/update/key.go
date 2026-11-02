package update

// ReleaseKey is the public ed25519 key releases are signed with. The
// private half lives only on the maintainer's machine, in
// ~/.config/wafisp-release/release.key (make release signs with it); the
// panel installs nothing that this key did not sign.
const ReleaseKey = "unUQDA8ou/JRif5MOee9F5g3qnyasgwa8JuSVOGbbmU="
