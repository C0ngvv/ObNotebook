
# EQUAFL

EQUAFL, an AFL-based framework coupled with enhanced user-mode QEMU emulation, which leverages the full-system emulated environment to support the emulation offline. Specifically, it first migrates an emulated environment from one-time full-system emulation of the target application to the host machine, including the launch variables, the dynamically-generated files and the hardware peripherals data. Then EQUAFL uses its enhanced user-mode emulation to emulate system calls of network, inter-process communication, and system control behaviors at the user-level. By doing so, environment discrepancies between the embedded system and the host machine will not affect the execution of applications.

EQUAFL，一个基于afl的框架，加上增强的用户模式QEMU仿真，它利用全系统仿真环境来支持脱机仿真。具体来说，它首先将模拟环境从目标应用程序的一次性全系统模拟迁移到主机，包括启动变量、动态生成的文件和硬件外围设备数据。然后EQUAFL使用其增强的用户模式仿真来模拟用户级的网络、进程间通信和系统控制行为的系统调用。通过这样做，嵌入式系统和主机之间的环境差异将不会影响应用程序的执行。

## Getting Started

### Requirements

**EQUAFL** has been deployed with docker, so we only need to run the docker image as follows. (NOTE: thare are some issues in uploading the large docker image file to zenodo, so we upload it to docker hub instead.)

**EQUAFL**已经和docker一起部署了，所以我们只需要运行docker镜像，如下所示。(注意:在将大的docker镜像文件上传到zenodo时存在一些问题，所以我们将其上传到docker hub。)

```
docker pull zyw200/equafl_artifact:0.4
docker run -it --env USER=root --privileged zyw200/equafl_artifact:0.4 /bin/bash	
cd /home/yaowen/firmadyne
```

### Basic functionality
We  run the following command to configure the image in EQUAFL_bench_test for testing.

我们运行以下命令来配置EQUAFL_bench_test中的映像以进行测试。

```
python EQUAFL_setup.py 0
```

Estimated Time < 5min,  Expected Output: no alert of **kpartx failed, no loop device to mount, maybe you can re-try by restarting the docker**

估计时间< 5min，期望输出：没有警报**kpartx失败，没有循环设备挂载，也许你可以重新启动docker**重试

The basic functionality of **EQUAFL** is evaluated from three aspects: compatibility, efficiency, and vulnerability discovery capability.

**EQUAFL**的基本功能从兼容性、效率和漏洞发现能力三个方面进行评估。

Run EQUAFL and baselines (Firm-AFL，AFL-FULL), and collect the execution speed and system call traces. Each baseline first executes to emulation stage and then runs into fuzzing process. Note that the fuzzing process will stop automatically. (Estimated Time < 10min)

运行EQUAFL和基线(Firm-AFL,AFL-FULL)，收集执行速度和系统调用跟踪。每条基线首先执行到仿真阶段，然后进入模糊过程。注意，模糊过程将自动停止。(预计时间< 10min)

```
python time_bench.py 0
python time_full_bench.py 0
python time_firmafl_bench.py 0
```

Expected Output: 	
The average time per seed (5 times) results are saved in **time_equafl, time_firmafl, time_full** dirs respectively.
The system call traces results are saved in **syscall_trace_aflfull** and **syscall_trace_equafl**

预期输出:每个种子平均时间(5次)的结果分别保存在**time_equafl, time_firmafl, time_full** 目录中。系统调用跟踪结果保存在“**syscall_trace_aflfull**”和“**syscall_trace_equafl**”目录下

#### Efficiency evaluation 

```
python collect_efficiency.py
```

Expected Output: the execution speed (test cases/s) of EQUAFL is higher than that of  Firm-AFL and AFL-FULL.

预期输出:EQUAFL的执行速度(测试用例/s)高于Firm-AFL和AFL-FULL。

#### Compatibility evaluation

```
python collect_compat.py
```

Expected Output: the system call similarity is 100%

预期输出:系统调用相似度为100%

#### Vulnerability discovery
Run the command to configure the specific image (image_id = 18627)

运行命令配置特定映像(image_id = 18627)

```
python EQUAFL_setup.py 18627
```

Expected Output: no alert of **kpartx failed, no loop device to mount, maybe you can re-try by restarting the docker**

期望输出:没有警报**kpartx失败，没有循环设备挂载，也许你可以重新启动docker**重试

Sometimes, the typed input cannot be shown, please use the command

有时，键入的输入不能显示，请使用命令

```
stty echo
```

Start the fuzzing process for the image

开始镜像的模糊处理过程

```
python vul_run.py 18627
```

Run the command (out of docker）to stop the fuzzing process at any time

运行命令(out of docker)随时停止fuzzing进程

```
ps -aux | grep qemu |awk '{print $2}'| xargs kill -9
```

Expected Output: the fuzzing process can find  unique crashes in 5min.

## Detailed Description
In Getting Started section, we only evaluate the EQUAFL and baselines on one image.
In Detailed Descriptions, we describe the evaluation of all claims as follows.
For compatibility and efficiency evaluation, we can evaluate it on all firmware images by replacing the item in **EQUAFL_bench_test** with that of **EQUAFL_bench_compat**, which contains all images (66 images successfully emulated by EQUAFL）

在入门部分中，我们只评估一张镜像上的EQUAFL和基线。在“详细描述”中，我们对所有权利要求的评估如下。为了兼容性和效率评估，我们可以通过将**EQUAFL_bench_test**中的项替换为**EQUAFL_bench_compat**中的项来评估所有固件映像，其中包含所有映像(EQUAFL成功模拟了66个映像)

For the vulnerability discovery evaluation on six firmware samples,  we can run following commands to start fuzzing of EQUAFL and baselines (AFL-Full, and Firm-AFL).

对于六个固件样本上的漏洞发现评估，我们可以运行以下命令来启动EQUAFL和基线(AFL-Full和Firm-AFL)的模糊化。

```
python vul_run.py 18627
python vul_run_firmafl.py 18627
python vul_run_aflfull.py 18627
```

The image shown in our paper is (image id: 16385, 2563, 109080, 18627, 7023, 106869)

本文中显示的镜像是(镜像id: 16385, 2563, 109080, 18627, 7023, 106869)

## Extension
If the user obtain another firmware, which is not involved in our dataset, you can follow the instructions to attemp to run it in EQUAFL.

如果用户获得了另一个固件，它不在我们的数据集中，您可以按照说明尝试在EQUAFL中运行它。

1. Follow the USAGE of firmadyne (https://github.com/firmadyne/firmadyne) to setup the images, and ensure that the image (\<imageId\>.tar.gz) exists in firmadyne/images/ dir.
2. Write configurations like (image_id;vendor;model;ip) in EQUAFL_bench_test
3. Run command "python EQUAFL_setup.py \<imageId\>"
4. Run command "python vul_run.py \<imageId\> to start the fuzzing.

1. 遵循firmadyne (https://github.com/firmadyne/firmadyne)的USAGE来设置映像，并确保映像(\<imageId\>.tar.gz)存在于firmadyne/images/ 目录中。
2. 在EQUAFL_bench_test 中写入类似(image_id;vendor;model;ip)的配置。
4. 执行命令"python EQUAFL_setup.py \<imageId\>"
5. 执行命令"python vul_run.py \<imageId\> "开始fuzzing。