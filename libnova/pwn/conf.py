"""
Default config for pwntools.

This most likely isn't what you (a normal human) wants
unless you have installed `https://github.com/novafacing/ubuntu-rc`
"""

from pwn import context

context.terminal = ["kitty", "-e", "sh", "-c"]  # pylint: disable=assigning-non-slot
