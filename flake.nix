{
  description = "ebpfw development tools";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  outputs = { self, nixpkgs }: let
    systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
  in { devShells = nixpkgs.lib.genAttrs systems (system: let pkgs = import nixpkgs { inherit system; }; in {
    default = pkgs.mkShell { packages = with pkgs; [ go llvmPackages.clang-unwrapped llvm gnumake (python3.withPackages (p: [ p.matplotlib ])) qemu squashfsTools zstd ]; };
  }); };
}
