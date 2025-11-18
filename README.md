# seccomp-dump

## what?

A basic utility that does what `seccomp-tools dump` does.

## why?

`seccomp-tools` is written in Ruby, and it may just be me, but having multiple Ruby versions in one machine is a mess. Even when using `rbenv`, it's still a mess. When I want to run `seccomp-tools dump` I don't want to go through the struggle of trying to understand why my Ruby installation is not working or how to solve it; I just want to see the seccomp rules and keep my workflow as smooth as possible.

## what's missing?

This only implements basic `dump` command. If you need the other features like `asm`, `disasm`, or `emu`, you'll need the original [seccomp-tools](https://github.com/david942j/seccomp-tools).

## build

```bash
make
```

## usage

```bash
# dump seccomp rules from a binary 
./seccomp-dump <binary>
```

## install (optional)

```bash
sudo make install
```

## contribute

This is just a small program I wrote while playing a CTF challenge. It's no big project or anything, but I think it might be helpful to someone else so I'm sharing it here.

If you want to contribute, you're welcome.

## disclaimer

This is not a complete tool, potentially full of bugs.
