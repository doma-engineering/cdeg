{
  description = "Flake for building rootrunner with standard overlaid Rust and OpenSSL support";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
    rust_overlay = {
      url = "github:oxalica/rust-overlay";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust_overlay, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust_overlay.overlays.default ];
        };
        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" "rust-analyzer" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rust

            pkg-config
            sqlx-cli
            postgresql
            sqlite
            nodejs
            pnpm
            zip
            unzip
            rsync
            openssl.dev
            openssl

            chromedriver
            chromium
            xvfb-run

            typescript
            nodePackages.typescript

            docker
	    docker-compose
          ];
        };

        devShell = self.devShells.${system}.default;
      }
    );
}
