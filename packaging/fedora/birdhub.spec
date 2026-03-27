Name:           birdhub
Version:        0.1.0
Release:        1%{?dist}
Summary:        Zero-Trust Virtual ISP agent and Hub control plane

License:        Proprietary
URL:            https://orbit.lfam.us
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  systemd-rpm-macros

Requires:       nftables
Requires:       iproute
Requires:       shadowsocks-rust
# Netbird might not be in official repos, but we require it
Requires:       netbird

%description
VISP (Virtual ISP) is a Zero-Trust overlay network architecture engineered for secure,
segmented routing. It combines NetBird (Identity Provider & Mesh) with Shadowsocks
(Encrypted Transport Layer) to ensure identity-verified, deeply encrypted network tunnels.
It operates in Hub (Control Plane) or Client (Transparent OS Router) modes.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release --locked

%install
rm -rf %{buildroot}

# Install binary
install -d %{buildroot}%{_bindir}
install -pm 755 target/release/%{name} %{buildroot}%{_bindir}/%{name}

# Install configuration file
install -d %{buildroot}%{_sysconfdir}/%{name}
install -pm 644 config.toml %{buildroot}%{_sysconfdir}/%{name}/config.toml

# Install systemd service
install -d %{buildroot}%{_unitdir}
install -pm 644 packaging/%{name}.service %{buildroot}%{_unitdir}/%{name}.service

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
%license LICENSE
%{_bindir}/%{name}
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/config.toml
%{_unitdir}/%{name}.service

%changelog
* Thu Mar 27 2024 VISP Engineering <admin@orbit.lfam.us> - 0.1.0-1
- Initial package release for Fedora
