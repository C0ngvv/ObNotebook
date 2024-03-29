# Jetset: Targeted Firmware Rehosting for Embedded Systems

![](images/Pasted%20image%2020231009145619.png)
Usenix 2021
# 翻译
在模拟器中执行代码的能力是现代漏洞测试的基本部分。不幸的是，这给许多嵌入式系统带来了挑战，其中固件期望与特定于目标的硬件设备进行交互。要使嵌入式系统固件在其本机环境之外运行(称为重新托管)，需要以足够的精度模拟这些硬件设备，以使固件确信它正在目标硬件上执行。然而，目标设备的全保真仿真(这需要相当大的工程努力)可能没有必要将固件引导到分析人员感兴趣的点(例如，可以注入模糊器输入的点)。我们假设，要使固件成功启动，只模拟固件预期的行为就足够了，并且这种行为可以自动推断出来。

为了验证这一假设，我们开发并实现了Jetset，这是一个使用符号执行来推断固件期望目标设备的行为的系统。Jetset可以用C语言生成硬件外设的设备模型，允许分析人员在模拟器(例如，QEMU)中引导固件。我们成功地将Jetset应用到13个不同的固件上，这些固件代表了三种架构、三个应用领域(电网、航空电子设备和消费电子产品)和五种不同的操作系统。我们还演示了Jetset辅助重托管如何促进航空电子嵌入式系统上的模糊测试(一种常见的安全分析技术)，在该系统中，我们发现了一个以前未知的特权升级漏洞。

## 1.引言
在受控环境中执行代码是现代系统分析的基本部分。不幸的是，嵌入式系统带来了挑战，因为它们的代码期望与专用的片内和片外外设(如通用I/O (GPIO)端口、传感器和通信接口)交互。执行环境必须以足够的保真度模拟这些设备，以确保观察到的行为准确地模拟在硬件上运行的目标系统。然而，由于外设的种类繁多，大多数都不是由执行环境建模的，这为我们最强大的分析技术创造了相当大的盲点。实际上，可能根本没有关于目标系统的文档，这使得为它构建一个完整的模拟器几乎是不可能的。

然而，在许多情况下，系统分析人员感兴趣的代码并不是与外设交互的代码。虽然不能完全忽略外设——硬件初始化必须成功，系统才能成功启动——但可能并不需要所有设备的正确行为。例如，对目标如何响应网络流量感兴趣的分析人员可能不需要执行环境忠实地模拟系统GPIO端口或其他通信接口的所有方面。

这项工作的主题是Jetset，这是一个执行有针对性的固件重托管的系统——它只使用其固件自动推断嵌入式系统外围设备的预期行为，然后合成一个足以引导到感兴趣的安全关键代码的外围设备模型。


