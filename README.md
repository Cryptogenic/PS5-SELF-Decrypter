# PS5 SELF Decrypter

A payload that uses kernel arbitrary read/write to decrypt Signed ELFs (SELFs) from the filesystem and dump the
plaintext ELFs to USB drive.

## Notes
- Replace `PC_IP` and `PC_PORT` macros on lines 24-25 with your TCP server's IP/port
  - It's recommended you use logging to know how far the payload's progressed or if it's stalled
- Plug compatible USB drive into PS5 with at least 1GB of free space before running
- Files will be dumped to `[USB root]/PS5/`
- Should support 3.xx-4.xx, but not tested on all firmwares (open an issue for any problems)
- Currently, the payload assumes pre-jailbroken state (ie. escaped sandbox), adding jailbreak code here is a TODO
- If you notice log activity has stopped for more than a minute, hard powerdown the PS5 via power button for three beeps
  and restart the console and run again
- The console may panic in the midst of dumping files, this is fine, restart the console and run again
  - The payload will pick up where it left off and continue dumping from where it was halted previously
- Improvements to make the payload less janky are welcome

## TODO
- [ ] Add code to escape sandbox in case the environment isn't already jailbroken
- [ ] Perform better locking on shared data access to improve stability
- [ ] Clean up various functions

## Example log
```
[+] kernel .data base is ffffffff88e40000, pipe 12->13, rw pair 14->21, pipe addr is ffffa04b61800480
[+] firmware version 0x3000038 ( 3.000.038)
[+] got auth manager: 4
...
[+] dumping /system_ex/common_ex/lib...
[+] decrypting /system_ex/common_ex/lib/libSceJsc.sprx...
  [?] decrypting block info segment for 0
  [?] decrypting block info segment for 1
  [?] decrypting block info segment for 2
  [?] decrypting block info segment for 4
  [?] decrypting block info segment for 9
  [?] decrypting block info segment for 10
  [?] decrypting segment=1, block=1/593
  [?] decrypting segment=1, block=2/593
  [?] decrypting segment=1, block=3/593
  [?] decrypting segment=1, block=4/593
```

## Notes for offset porting
- One of the goals in writing this payload was keeping it somewhat easy to port to other firmwares, even without kernel
  .text dump
- The payload will use lib calls to determine the system version and tailor at runtime, assuming that firmware has
  support
- There are a total of 11 offsets, notes for finding them are as follows (these are not guaranteed, but based on observations):
  - `offset_authmgr_handle`: +0x30 bytes from pointer to "sdt" string (it should also usually be 0x4)
  - `offset_sbl_mb_mtx`: -0x20 bytes from pointer to "SblDrvSendSx" string
  - `offset_mailbox_base`: +0x8 bytes from `offset_sbl_mb_mtx`
  - `offset_sbl_sxlock`: +0x8 bytes from `offset_mailbox_base`
  - `offset_mailbox_flags`: -0x8 bytes from pointer to "req mtx" string
  - `offset_mailbox_meta`: -0x18 bytes from pointer to "req msg cv" string
  - `offset_dmpml4i`: -0x8 bytes from pointer to "invlgn" string
  - `offset_dmpdpi`: +0x4 bytes from `offset_dmpml4i`
  - `offset_pml4pml4i`: -0x1C bytes from pointer to "pmap" string
  - `offset_datacave_1/offset_datacave_2`: any two 0x4000 byte ranges that seem unused (likely dont need changing)

## Thanks
- ChendoChap (various reversing help and testing)
- Znullptr (testing)
- flat_z (kernel to work off of + various info)
- alexaltea (previous work w/ orbital for reference)

## License
Specter (Cryptogenic) - [@SpecterDev](https://twitter.com/SpecterDev)

This project is licensed under the unlicense license - see the [LICENSE.md](LICENSE.md) file for details.
