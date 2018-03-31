
Debian
====================
This directory contains files used to package nixd/nix-qt
for Debian-based Linux systems. If you compile nixd/nix-qt yourself, there are some useful files here.

## nix: URI support ##


nix-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install nix-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your nix-qt binary to `/usr/bin`
and the `../../share/pixmaps/nix128.png` to `/usr/share/pixmaps`

nix-qt.protocol (KDE)

