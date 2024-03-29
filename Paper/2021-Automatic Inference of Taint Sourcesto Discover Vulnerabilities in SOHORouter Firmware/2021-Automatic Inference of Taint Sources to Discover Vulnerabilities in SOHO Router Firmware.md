---
title: 2021-Automatic Inference of Taint Sources to Discover Vulnerabilities in SOHO Router Firmware
date: 2023/12/07
categories:
  - 论文
tags:
  - 论文翻译
---

# 2021-Automatic Inference of Taint Sources to Discover Vulnerabilities in SOHO Router Firmware



## 摘要
近年来，针对SOHO(小型办公室和家庭办公室)路由器的网络攻击引起了人们的广泛关注。黑客利用的漏洞大多发生在路由器固件的web服务器上。在漏洞检测中，与动态分析(例如，模糊测试)相比，静态污染分析可以快速覆盖所有代码，而不依赖于运行时环境。然而，由于缺乏对间接调用的解析，现有的静态分析技术存在较高的假阴性率，这使得从公共源(例如，recv)到接收器跟踪受污染的数据变得具有挑战性。在这项工作中，我们提出了一种新的启发式方法来应对这一挑战。我们不解决间接调用，而是通过识别具有键值特征的函数来自动推断污染源。我们可以使用推断的污染源绕过间接调用，并通过静态污染分析跟踪污染以检测漏洞。我们实现了一个原型系统，并在5家供应商的10个流行路由器上对其进行了评估。该系统发现了245个漏洞，包括41个为期1天的漏洞和204个以前从未暴露过的漏洞。实验结果表明，与目前最先进的模糊测试工具相比，我们的系统可以发现更多的错误。

## 1.引言
物联网(IoT)是过去十年中发展最快的新兴技术之一。根据Statista的研究，到2025年，全球将安装超过215亿台有源物联网设备[16]。它们通常通过小型办公室和家庭办公室(SOHO)路由器连接到互联网。不幸的是，由于缺乏先进的防御机制和面向互联网的特性，SOHO路由器成为了远程攻击的温床[17]。例如，2019年，Mirai的新变种Echobot登陆互联网[9]。这种复杂的攻击利用了各种SOHO路由器中的多达71个漏洞，导致了严重的后果，例如远程代码执行和命令注入。

大多数SOHO路由器实现了一个定制的web服务器来管理和配置设备的功能。HTTP服务器是常用的web服务器之一，它通过HTTP协议提供网络服务。这些web服务器直接接收来自网络的请求，这些请求是攻击者控制的数据，使它们容易受到漏洞的影响。近年来，针对SOHO路由器漏洞的发现工作有很多，包括静态分析[6,13]和动态分析[5,20 - 22]。SOHO路由器中发现的大多数漏洞都与web服务器有关。在本文中，我们还旨在发现SOHO路由器web服务器中的漏洞。

在动态分析中，主流的方法是通过模拟固件的灰盒模糊测试[21,22]或物理设备的黑盒模糊测试[5,20]来发现漏洞。然而，这两种方法目前都面临着传统模糊测试本身的问题，比如代码覆盖率低，会导致大量的假阴性结果。在静态分析中，相关工作[6,13]利用静态污染分析发现了一类被称为污染式漏洞的漏洞，即数据从攻击者控制的源传递到安全敏感的接收器而不进行消毒[19]。与动态分析相比，静态分析测试代码，而不是在运行时环境中实际执行代码，因此是测试路由器固件的更实用和经济的选择。例如，静态分析可以分析大量路由器的固件，而不需要昂贵的实际设备。此外，对于某些类型的漏洞检测，静态分析可以实现更高的代码覆盖率和更低的误报。在这项工作中，我们专注于使用静态分析来查找SOHO路由器固件中的污点式漏洞。

**发现污点式漏洞的挑战**。从本质上讲，发现污点式漏洞的有效性在很大程度上依赖于一个好的数据依赖分析工具;实际上，为了发现缺陷，工具必须构造一条路径，在该路径中，污染从攻击者控制的源传播到安全敏感的接收器。然而，在二进制分析中，间接调用的存在使得现有的静态污染分析技术很难从公共源(例如，recv)到接收器跟踪受污染的数据。结果，许多漏洞被遗漏了。尽管现有的工作使用启发式方法绕过间接调用并发现了污染式漏洞的子集，但这些启发式方法效率低下。例如，在DTaint[6]中，作者手动指定了一些供应商自定义的函数(例如，find_var和websGetVar)作为污染源。在KARONTE[13]中，作者使用预设的网络编码字符串列表(如“soap”或“HTTP”)作为关键字来推断污染源。然而，前者需要通过固件逆向工程手动查找特殊功能;后者的启发式方法不够全面，无法推断出带有未知字符串的污染源(例如图1中的“entrys”)。

![](2021-Automatic%20Inference%20of%20Taint%20Sources%20to%20Discover%20Vulnerabilities%20in%20SOHO%20Router%20Firmware/image-20231207213726501.png)

**我们的方法**。为了解决这些挑战，我们提出了一种新的启发式方法来自动推断污染源，而不是解决间接调用。具体来说，我们观察了一类函数，它们通过索引用户请求中的关键字来获取值。这些值由攻击者控制，因此，这些函数可以作为污点源，用于污点式漏洞检测。通过推断这些污染源，我们的污染分析不一定从共同的来源(例如，recv)开始。相反，它可以直接从推断的污染源开始。在本文中，我们将这些函数称为key-value函数。为了识别键-值函数，我们首先总结这些函数的特征，并通过数据流分析找到键-值函数。其次，一些键值函数在本地而不是从网络获取数据，因此我们对这些函数进行过滤以减少误报。第三，生成污染源摘要，并将其传递给静态污染分析引擎进行漏洞检测。我们实现了一个原型系统，并在5家供应商的10个流行路由器上对其进行了评估。该系统发现了245个漏洞，包括41个为期1天的漏洞和204个以前从未暴露过的漏洞。

**贡献**。综上所述，我们在本文中做出了以下贡献:
- 提出了一种在SOHO路由器固件上自动推断污染源的新方法。利用推断的污染源，我们实现了对二进制文件的静态污染分析，以发现漏洞。
- 我们实现了一个系统原型，并在10个真实固件映像上对其进行了评估，结果表明我们的工具可以成功找到键值污染源，从而发现245个漏洞。与最先进的模糊测试工具相比，我们的原型可以发现更多的漏洞。

## 2.背景与动机
### 2.1 SOHO路由器的典型架构
除了提供路由网络服务外，SOHO路由器通常还利用内置的web服务器进行管理和配置。然后，用户可以通过浏览器连接到路由器的管理界面，配置路由器的各种功能，如设置无线密码、IP地址、白名单等。此外，一些路由器厂商还提供移动app来管理设备[5]。管理和配置通常基于标准协议，如超文本传输协议(HyperText Transfer Protocol, HTTP)，它们的典型实现由前端、后端和数据库组成。前端提供接口指导用户配置路由器，后端处理用户请求并解析请求执行相应功能，数据库存储获取的配置[20]。

### 2.2 Key-Value特性
发送到SOHO路由器的典型用户请求包含一个URL和几个不同的键值对。当接收到请求时，后端解析请求以获得键和相应的值。然后webserver根据获取到的值配置路由器。然而，该程序通常缺乏对这些值的安全检查，从而导致许多漏洞，例如内存损坏、命令注入、跨站点脚本(XSS)。

**动机案例**。我们将在下面的示例中演示这一点，该示例基于真实的固件映像。图1的左半部分显示了POST请求，图1的右半部分显示了在后端处理请求的过程。此示例对应两个已知漏洞，CVE-201818708和CVE-2020-13390。POST数据包含三个参数键:“entrys”、“mitInterface”和“page”。当在后端处理这些参数键时，它们的值由websGetVar函数通过索引键(第3、4和8行)读取，并直接传递给sprintf，而不进行任何处理。因此，当字符串条目的长度或字符串ifindex的长度大于0x200时，可能会在第6行触发基于堆栈的缓冲区溢出。当字符串页的长度大于0x100时，可能会在第10行触发另一个基于堆栈的缓冲区溢出。

![](2021-Automatic%20Inference%20of%20Taint%20Sources%20to%20Discover%20Vulnerabilities%20in%20SOHO%20Router%20Firmware/image-20231207213726501.png)

**Key-Value函数模型**。在图1中，函数websGetVar匹配数据结构wp中的一个键并返回一个值。在本文中，我们将像websGetVar一样的函数称为key-value函数。我们的目标是自动识别键值函数并通过静态污染分析跟踪值来发现漏洞。

不同的SOHO路由器厂商以不同的方式实现键值函数。根据我们的观察，键-值函数有两种主要的实现方法:值由键索引并且，(a)由指针形参保存，或(b)由返回指针保存。如图2所示，这两种实现方法的抽象C代码分别对应函数KeyValue1和KeyValue2。对于图2(a)中的函数KeyValue1，输入的数据是用户发布的原始请求。KeyValue1通过调用一个类似字符串的函数(第3-5行)在input中查找关键字key，从而获得相应值的地址v索引。在检查一些特殊字符之后，通过循环将原始值复制到参数值所指向的缓冲区(第6-7行)。对于图2(b)中的函数KeyValue2，原始请求被分割成(键、值)对并保存到一个结构对象sd中。然后，KeyValue2通过调用类似strcmp的函数对关键字key进行索引，并返回值sd->value(第3-7行)。

![](2021-Automatic%20Inference%20of%20Taint%20Sources%20to%20Discover%20Vulnerabilities%20in%20SOHO%20Router%20Firmware/image-20231207214730285.png)

在键值函数的两种实现中有一些特性。(1)key特性:Key的参数直接传递到在循环中调用的类strcmp函数的参数中;(2)值特征:指向值的指针依赖于一个参数(如KeyValue1)或返回值(如KeyValue2)，数据依赖图中包含一个循环;(3)约束特性:key-value函数可能有一个常数参数来限制值的长度。然而，这个特性是可选的，并不总是存在于实现中。

此外，调用key-value函数处理请求的行为还具有2个附加特征:(4)高频特征:key-value函数在不同的调用地点被多次调用。(5)大量关键词特性:不同的调用点会引用到各种常量关键字。

除了上面描述的两种实现方法外，有些函数是键值函数的包装器。这些函数也具有键值功能，但它们本身不实现键特性和值特性。如图2(c)所示，函数KeyValue3调用键值函数KeyValue2获取值v索引，并通过调用类结构函数将其复制到参数值指向的内存块中。函数KeyValue4调用键值函数KeyValue2来获取值v索引并返回它。

为了更好地描述下面的设计，我们将像KeyValue1这样的函数称为键值模型1，将像KeyValue2这样的函数称为键值模型2，将像KeyValue3或KeyValue4这样的函数称为键值模型3。

## 3.详细设计
在本节中，我们将详细说明系统的设计。如图3所示，所提出的系统由两个主要部分组成。它的输入是嵌入式系统中使用的主流架构(例如ARM, MIPS)的二进制文件。为了实现与体系结构无关，它首先将二进制机器码转换为中间表示(IR)[11]。因此，本文提出了基于VEX IR的静态二进制分析，VEX IR是一种流行的IR，广泛应用于许多程序分析工具中，包括Valgrind[11]和Angr[15]。为了推断污染源，它首先通过静态分析识别键值特征。然后，它通过从固件映像提取的本地文件中检索关键字来过滤键值函数。最后，对污染源函数进行汇总，并将汇总信息传递给静态污染分析引擎进行漏洞检测。为了发现漏洞，它首先初始化来自推断的污染源的数据，并通过静态污染分析跟踪污染。然后，它根据受污染数据的约束检测受污染类型的漏洞。

![](2021-Automatic%20Inference%20of%20Taint%20Sources%20to%20Discover%20Vulnerabilities%20in%20SOHO%20Router%20Firmware/image-20231207215535441.png)

### 3.1 键值污染源推断
本节介绍如何通过静态分析识别键值特征来推断污染源。

**识别键值函数**。正如我们在2.2节中提到的，典型的键值函数具有以下几个明显的特征:key特征、value特征、约束特征、高频特征和大量关键字特征。

为了找到上述五个特性，我们的系统首先使用市场上最强大的逆向工程工具IDA Pro来自动识别目标二进制中的函数。然后，通过高频特征来选择候选函数，而不是对所有函数进行分析，从而提高了分析效率。根据我们的实验，键值函数通常被调用100次以上，这是过滤的阈值。为了识别大量关键字特性，我们的系统在不同的调用点分析每个候选函数的上下文，以检查它是否包含指向常量字符串的指针参数。如果没有找到或找到的常量字符串的次数不超过候选函数调用次数的一半，系统将从候选集中删除该函数。对于约束特性，我们的系统还分析了函数的上下文，以总结在不同的调用地点是否为相同的参数分配了常量值。如果找到，则将参数标记为值的长度约束。在下文中，我们将说明如何通过对剩余候选函数的数据流分析来识别key特征和value特征。

首先，我们的系统采用与[13]中提出的方法相同的方法来自动识别类strcmp函数。其次，对于候选函数，我们的系统生成控制流图(CFG)并遍历CFG以查找循环。如果CFG包含一个循环，并在循环中调用了一个类似strcmp的函数，我们的系统将通过遵循常规的use-def链来向后跟踪这个类似strcmp的函数的参数。如果一个类strcmp的函数参数依赖于候选函数的一个形参，则key特性被识别。第三，对于模型一中的值特征，value中的字节通过循环从一个缓冲区移动到另一个缓冲区，其中另一个缓冲区的地址是候选函数的指针参数。我们的系统向前跟踪候选函数的所有参数，并试图找到一个参数，这是一个指针，用于字节存储指令的地址(例如:在STRB R0, \[R4,R5]中的R4)。如果找到了，我们的系统向后跟踪字节存储指令的地址(例如，寄存器R4,R5)来生成一个数据依赖图(DDG)。如果DDG中存在循环，则找到值特征。因此，候选函数被识别为键值模型函数。否则，我们的系统将向后跟踪候选函数的返回值以生成DDG。如果DDG中存在循环，则将候选函数识别为键值模型2。

> [13]Redini, N., et al.: Karonte: detecting insecure multi-binary interactions in embedded firmware. In: SP (2020)

如果候选函数既不是键值模型1，也不是键值模型2，我们确定它是否是键值模型3。为了识别这个模型，我们的系统分析了它的所有调用者。如果有一个被调用者满足键值模型2的特征，我们的系统迭代分析它的调用者，并根据以下两个条件确定它的调用者是否为键值模型3。

(1) key-value函数和它的调用者有相同的参数key指向一个常量字符串。

(2)对于像KeyValue3这样的函数，调用者的返回值取决于键值函数的返回值。对于像KeyValue4这样的函数，从键值函数返回的值被复制到调用者的指针参数所指向的内存块中。复制是由一些库函数实现的(例如，strcpy, strncpy, memcpy等)。

一旦创建了一个新的键-值函数，我们的系统将根据上述两个条件继续分析它的调用者，直到没有找到其他键-值函数。

**过滤键值函数并生成污染源摘要**。还有一些函数显示了这些特性，但它们不处理来自网络输入的键值对(例如，解析本地配置文件)。从本地文件读取的值不受攻击者控制。因此，不应将这些键值函数视为污染源。我们在下面介绍了如何过滤它们。首先，我们的系统在每个已识别的键-值函数的调用上下文中收集所有常量关键字。然后，我们的系统提取固件映像中的所有文件，并用正则表达式匹配文本中的内容，查找key=value或key:value等字符串。最后，如果一个键-值函数的大部分关键字(超过该键-值函数被调用次数的80%)都在本地文件中，则不将该键-值函数视为污染源。此外，我们的系统会过滤调用不超过100次的键值函数。

对于已识别的污染源，我们的系统总结了它们的参数和返回值。摘要信息包括需要被污染的参数或返回值，参数表示关键字的值和参数的长度约束。此信息被传递给静态污染分析引擎，用于检测污染类型的漏洞。

### 3.2 静态污点分析
静态污染分析旨在通过跟踪来自上述污染源的污染数据来查找污染类型的漏洞。

**污点初始化和传播**。我们的系统不是从程序的入口点(例如main)开始，而是从调用污染源的函数开始。它根据其摘要信息将调用污染源的每个调用点的参数寄存器或返回寄存器标记为具有唯一id的污染。唯一id可以区分来自不同调用点的受污染数据，并帮助我们将受污染数据与各种关键字相关联。然后，通过对VEX IR的语句和表达式的分析，受污染的数据沿着def-use链向前传播。在正向污染分析中，表1显示了污染传播规则。特别地，当IR语句的操作符是比较(例如，binop是CmpLE)并且受污染的数据是其操作数之一时，我们的系统收集约束(例如，x<8，其中x是受污染的)。此外，如果比较操作数不是常量(例如，x<y，其中x是污点)，我们的系统后向追踪操作数y来在当前函数内找到它的值。如果发现操作数y被赋值为常数，则系统更新相应的约束。

![](2021-Automatic%20Inference%20of%20Taint%20Sources%20to%20Discover%20Vulnerabilities%20in%20SOHO%20Router%20Firmware/image-20231208194147289.png)

另一个需要考虑的问题是用load和store操作的内存访问之间的污染传播规则。如表1所示，加载操作LDle对应两条规则tj→ti和∗tj→ti。前者表示从受污染的地址tj中读取值ti，并将值ti标记为taint。在这种情况下，加载的值ti可以是整数或字符。后者表示指针tj所指向的对象是受污染的数据，而加载的对象ti被标记为受污染。在这种情况下，先前通过STle操作存储在内存中的受污染数据将使用相同的地址加载。对于内存访问中的污染传播，我们的系统只跟踪具有相同寄存器基址和常量偏移量的全局地址、堆栈地址和简单的间接内存访问(例如，STle(r0 + 0x20)和LDle(r0 + 0x20))。

在过程间污染分析中，我们采用生成污染摘要的方法来提高污染分析的效率。当在污染分析中遇到一个被调用者时，如果它的参数没有被污染，系统就忽略它。否则，我们的系统将跟踪被调用者并为被调用者生成摘要。污染摘要描述了输入的污染参数，以及在分析被调用程序后污染的新参数或返回值。因此，当遇到相同的被调用者时，如果被跟踪的受污染数据在被调用者的污染摘要中，我们的系统使用摘要来快速传播污染。否则，它将再次分析被调用者并更新污染摘要。

对于库函数，我们的系统还采用了污染摘要来传播污染。它们的摘要是手动生成的，我们只是为一些常见的与字符串相关的库函数(例如，strcpy, memcpy, strstr, strcmp等)实现摘要。例如，当满足库函数strcpy(\*dest， \*src)时，变量从参数src传播到参数dest。在变量分析中，如果库函数不实现摘要，则不遵循它们。

**漏洞检查**。在我们的系统中，我们主要发现了基于堆栈的缓冲区溢出和命令注入漏洞。当到达string-copy sink时，例如strcpy(\*dest, \*src)，并且目标dest指向的副本内存块是堆栈地址，我们的系统首先计算目标缓冲区的最大大小max_buffer。然后，我们的系统检查受污染数据的约束。如果约束为空，则生成警报。如果约束不为空并且包含符号约束，则接收器是安全的，不会生成警报。例如len < x，其中符号len是包含的指针所指向的字符串的长度，而符号x是一个符号值。否则，我们的系统求解约束以获得字符串长度len的最小值。如果最小值大于最大缓冲区，则产生警告。对于命令注入，如果污染到达命令执行接收器(例如，system和popen)，并且污染的约束为空，则生成警报。

## 4.评估
### 4.1 实现
我们已经使用python在VEX IR之上实现了一个原型。特别是，我们首先利用IDA Pro来识别函数并为目标程序生成控制流图(CFG)。然后，我们在生成CFG的基础上加载目标二进制文件，并通过Angr的API将汇编代码转换为VEX IR。最后，在此基础上，我们实现了数据流分析来推断键值函数和污点分析来发现漏洞。

### 4.2 实验设置
在实验中，我们从五个不同的供应商中选择了10个路由器的固件映像。表2显示了10个固件映像的汇总信息。我们利用Binwalk来解包固件映像并提取处理请求的web服务器程序。这些程序的架构包括目前SOHO路由器使用的主流架构ARM32和MIPS32。所有实验均在Ubuntu 18.04.4 LTS操作系统上进行，该操作系统采用64位8核Inter(R) Core(TM) i7-8550 CPU和24 GB RAM。

![](2021-Automatic%20Inference%20of%20Taint%20Sources%20to%20Discover%20Vulnerabilities%20in%20SOHO%20Router%20Firmware/image-20231208195438363.png)

## 7.结论
在这项工作中，我们提出了一种新的启发式方法来发现SOHO路由器固件映像中的漏洞，而无需处理间接调用。特别地，我们通过识别具有键值特征的函数来自动推断污染源。利用推断的污染源，通过静态污染分析跟踪污染，检测漏洞。我们实现了一个原型系统，并在5家供应商的10个流行路由器上对其进行了评估。该系统发现了245个漏洞，包括41个为期1天的漏洞和204个以前从未暴露过的漏洞。实验结果表明，与目前最先进的模糊测试工具相比，我们的系统可以发现更多的错误。
