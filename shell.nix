#!/usr/bin/env nix-shell

{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name="ec-elgamal";
  buildInputs = [
    pkgs.stack
  ];
}
