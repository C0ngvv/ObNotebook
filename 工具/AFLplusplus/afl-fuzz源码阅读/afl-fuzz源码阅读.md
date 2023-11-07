```
alf-fuzz -i input_dir -o output_dir -Q -m none binary
```
getopt()
`-i`

```
afl->in_dir = optarg;
if (!strcmp(afl->in_dir, "-")) { afl->in_place_resume = 1; }
```

-o
afl->out_dir = optarg;

-Q
```
if (afl->fsrv.qemu_mode) { FATAL("Multiple -Q options not supported"); }
afl->fsrv.qemu_mode = 1;
if (!mem_limit_given) { afl->fsrv.mem_limit = MEM_LIMIT_QEMU; }
```

