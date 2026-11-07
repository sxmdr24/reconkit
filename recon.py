#!/usr/bin/env python3
"""Thin wrapper so `python recon.py <target>` keeps working. See the reconkit package."""

from reconkit.cli import main

if __name__ == "__main__":
    main()
