{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell rec {
  buildInputs = with pkgs; [
    cargo
    cargo-bundle
    rustc
    cmake
    pkg-config
    openssl
  ];

}
