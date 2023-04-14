## 环境
使用的是该镜像
```bash
sudo docker pull mborgerson/firmadyne:auto
sudo docker run -it -v /home/cxw/firmadyne:/share mborgerson/firmadyne:auto /bin/bash
# sudo chown -R firmadyne:firmadyne /share
```

![](images/Pasted%20image%2020230414114546.png)

退出后再进入命令
```
sudo docker start 4b
sudo docker exec -it 4b /bin/bash
```

firmadyne目录下内容
![](images/Pasted%20image%2020230414090140.png)

## Firmadyne Usage
1. 设置`firmadyne.config` 文件中的`FIRMWARE_DIR` 指向firmadyne库的根目录。
2. 下载固件镜像，如Netgear WNAP320 v2.0.3
```
wget http://www.downloads.netgear.com/files/GDC/WNAP320/WNAP320%20Firmware%20Version%202.0.3.zip
```

3. 使用extractor来仅仅恢复文件系统，没有内核(`-nk`)，没有并行操作(`-np`)，在127.0.0.1的SQL服务器（-sql）中用Netgear品牌（-b）填充`image`表，并将打包文件存储在`images` 中。
```
./sources/extractor/extractor.py -b Netgear -sql 127.0.0.1 -np -nk "WNAP320 Firmware Version 2.0.3.zip" images
```

执行结果
```
firmadyne@4b955c5cb46d:/firmadyne$ python3 ./sources/extractor/extractor.py -b Netgear -sql 127.0.0.1 -np -nk /share/"WN
AP320 Firmware Version 2.0.3.zip" images
>> Database Image ID: 1

/share/WNAP320 Firmware Version 2.0.3.zip
>> MD5: 51eddc7046d77a752ca4b39fbda50aff
>> Tag: 1
>> Temp: /tmp/tmpsn906xqv
>> Status: Kernel: True, Rootfs: False, Do_Kernel: False,                 Do_Rootfs: True
>>>> Zip archive data, at least v2.0 to extract, compressed size: 1197, uncompressed size: 2667, name: ReleaseNotes_WNAP320_fw_2.0.3.HTML
>> Recursing into archive ...

/tmp/tmpsn906xqv/_WNAP320 Firmware Version 2.0.3.zip.extracted/WNAP320_V2.0.3_firmware.tar
        >> MD5: 6b66d0c845ea6f086e0424158d8e5f26
        >> Tag: 1
        >> Temp: /tmp/tmpv20q9nui
        >> Status: Kernel: True, Rootfs: False, Do_Kernel: False,                 Do_Rootfs: True
        >>>> POSIX tar archive (GNU), owner user name: "gz.uImage"
        >> Recursing into archive ...

/tmp/tmpv20q9nui/_WNAP320_V2.0.3_firmware.tar.extracted/kernel.md5
                >> MD5: 0e15e5398024c854756d3e5f7bc78877
                >> Skipping: text/plain...

/tmp/tmpv20q9nui/_WNAP320_V2.0.3_firmware.tar.extracted/root_fs.md5
                >> MD5: b43dc86ce23660652d37d97651ba1c77
                >> Skipping: text/plain...

/tmp/tmpv20q9nui/_WNAP320_V2.0.3_firmware.tar.extracted/rootfs.squashfs
                >> MD5: 7ce95b252346d2486d55866a1a9782be
                >> Tag: 1
                >> Temp: /tmp/tmph3j0tm9c
                >> Status: Kernel: True, Rootfs: False, Do_Kernel: False,                 Do_Rootfs: True
                >>>> XAR archive, version: -6057, header size: 2664, TOC compressed: 18154158142782153979, TOC uncompressed: 10765983841730652167
                >> Recursing into archive ...
                >>>> Squashfs filesystem, big endian, lzma signature, version 3.1, size: 4433988 bytes, 1247 inodes, blocksize: 65536 bytes, created: 2011-06-23 10:46:19
                >>>> Found Linux filesystem in /tmp/tmph3j0tm9c/_rootfs.squashfs.extracted/squashfs-root!
                >> Skipping: completed!
                >> Cleaning up /tmp/tmph3j0tm9c...
        >> Skipping: completed!
        >> Cleaning up /tmp/tmpv20q9nui...
>> Skipping: completed!
>> Cleaning up /tmp/tmpsn906xqv...
firmadyne@4b955c5cb46d:/firmadyne$
```

执行后在images目录下增加一个打包文件，里面内容是固件中的文件系统。

4. 识别固件1的架构，并将结果存储在数据库的`image` 表中
```
./scripts/getArch.sh ./images/1.tar.gz
```

![](images/Pasted%20image%2020230414103402.png)

5. 将固件1的文件系统内容加载到数据库中，填充`object` 和`object_to_image` 表。
```
./scripts/tar2db.py -i 1 -f ./images/1.tar.gz
```

6. 为固件1创建QEMU磁盘镜像
```
sudo ./scripts/makeImage.sh 1
```

7. 推断出固件1的网络配置。内核信息被记录到`./scratch/1/qemu.initial.serial.log`。
```
./scripts/inferNetwork.sh 1
```

8. 用推断出的网络配置模拟固件1。这将通过创建一个TAP设备和添加一个路由来修改主机系统的配置。
```
./scratch/1/run.sh
```

9. 系统应该可以通过网络使用，并准备好进行分析。内核信息被镜像到`./scratch/1/qemu.final.serial.log`。固件1的文件系统可以用.`/scripts/mount.sh 1`和`./scripts/umount.sh 1`从`scratch/1/image`挂载和卸载。
```
./analyses/snmpwalk.sh 192.168.0.100
./analyses/webAccess.py 1 192.168.0.100 log.txt
mkdir exploits; ./analyses/runExploits.py -t 192.168.0.100 -o exploits/exploit -e x (requires Metasploit Framework)
sudo nmap -O -sV 192.168.0.100
```

10. 默认的控制台应该会自动连接到终端。你也可以用`root`和`password`登录。注意，`Ctrl-c`会被发送到客户机；使用QEMU监控命令`Ctrl-a + x`来终止仿真。



