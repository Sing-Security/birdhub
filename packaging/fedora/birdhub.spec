Name:           birdhub
Version:        0.1.0
Release:        1%{?dist}
Summary:        Relay over Temper certificates: hub and client in one binary

License:        Proprietary
URL:            https://orbit.lfam.us
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  systemd-rpm-macros

# No runtime dependencies: the tunnel is an ordinary TCP connection, and the
# netbird/nftables/iproute2 dependencies of the first packaging are gone along
# with the code that needed them.
%global _description %{expand:
birdhub relays TCP through authenticated, encrypted Temper sessions. A hub
terminates sessions and dials the targets each client's certificate grants; a
client binds a local address and carries every connection it accepts to one
fixed destination through the hub. Identity is a certificate issued by a fleet
CA, authorization is the hub's grant table, and neither end needs privileges.}

%description
%{_description}

%prep
%autosetup -c -n %{name}-%{version}

%build
cargo build --release --locked

%check
cargo test --release --locked

%install
rm -rf %{buildroot}

install -d %{buildroot}%{_bindir}
install -pm 755 target/release/%{name} %{buildroot}%{_bindir}/%{name}

# Both role configs; each file's header documents the three enrollment
# commands that produce the keys, certificates and CA file they reference.
install -d %{buildroot}%{_sysconfdir}/%{name}
install -pm 644 hub-config.toml %{buildroot}%{_sysconfdir}/%{name}/hub-config.toml
install -pm 644 client-config.toml %{buildroot}%{_sysconfdir}/%{name}/client-config.toml

install -d %{buildroot}%{_unitdir}
install -pm 644 packaging/%{name}.service %{buildroot}%{_unitdir}/%{name}.service

install -d %{buildroot}%{_sysusersdir}
install -pm 644 packaging/%{name}.sysusers %{buildroot}%{_sysusersdir}/%{name}.conf

%post
%systemd_post %{name}.service
# The user is created by the sysusers.d file above, which Fedora's systemd
# file triggers process on install.

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
%license LICENSE
%{_bindir}/%{name}
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/hub-config.toml
%config(noreplace) %{_sysconfdir}/%{name}/client-config.toml
%{_unitdir}/%{name}.service
%{_sysusersdir}/%{name}.conf

%changelog
* Thu Oct 09 2026 LFAM Orbit <admin@orbit.lfam.us> - 0.1.0-1
- Replace NetBird-based identity with Temper certificates and hub grants
* Wed Mar 27 2024 VISP Engineering <admin@orbit.lfam.us> - 0.1.0-1
- Initial package release for Fedora
