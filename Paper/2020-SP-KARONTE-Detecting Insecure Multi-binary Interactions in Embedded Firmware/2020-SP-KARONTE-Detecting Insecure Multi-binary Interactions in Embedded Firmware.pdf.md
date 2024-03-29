---
title: 2020-SP-KARONTE-Detecting Insecure Multi-binary Interactions in Embedded Firmware.pdf
date: 2023/12/11
categories:
  - 论文
tags:
  - 论文翻译
---
# 2020-SP-KARONTE-Detecting Insecure Multi-binary Interactions in Embedded Firmware

## 摘要
低功耗、单一用途的嵌入式设备(如路由器和物联网设备)已经无处不在。虽然它们自动化并简化了用户生活的许多方面，但最近的大规模攻击表明，它们的数量之多对互联网基础设施构成了严重威胁。不幸的是，这些系统上的软件依赖于硬件，并且通常在具有非标准配置的独特最小环境中执行，这使得安全性分析特别具有挑战性。许多现有设备通过使用多个二进制文件来实现其功能。这种多二进制服务实现使得当前的静态和动态分析技术要么无效，要么效率低下，因为它们无法识别和充分建模各种可执行文件之间的通信。在本文中，我们提出KARONTE，一种静态分析方法，能够通过建模和跟踪多二进制交互来分析嵌入式设备固件。我们的方法在二进制文件之间传播污染信息，以检测不安全的交互并识别漏洞。我们首先在来自不同供应商的53个固件样本上对KARONTE进行了评估，结果表明我们的原型工具可以成功地跟踪和约束多二进制交互。这导致发现了46个零日漏洞。然后，我们在899个不同的样本上进行了大规模实验，结果表明KARONTE可以很好地适应不同大小和复杂程度的固件样本。

## 1.引言
由于小型互联嵌入式设备的激增，我们的世界的连通性正在急剧增加，这些设备正在取代传统的门锁、灯泡和许多其他以前不显眼的物体。不幸的是，在这些物联网(IoT)设备上运行的软件(或固件)很容易受到攻击[3]，[9]，[32]，这导致了地下物联网网络犯罪的发展[21]。例如，2016年，Mirai僵尸网络入侵了数百万台设备(如路由器和摄像头)，并利用它们进行拒绝服务攻击，破坏核心互联网服务并关闭网站[27]，[30]，[50]。

作为回应，研究人员提出了自动识别固件发行版中的漏洞的技术，通常是将它们解包为可分析的组件[11]，然后对其进行隔离分析[5]，[42]，[40]。然而，尽管漏洞发现技术取得了这些进步，但最先进的方法还不够，漏洞仍然存在。

当前技术不足的一个关键原因是嵌入式设备本身是由相互连接的组件组成的。这些组件是不同的二进制可执行文件，或者是大型嵌入式操作系统的不同模块，它们相互作用以完成各种任务。例如，嵌入式设备经常暴露由web服务器和各种后端应用程序组成的基于web的接口[6]，[44]。在这种架构中，任何给定的功能通常依赖于多个程序的执行\[12]:例如，接受HTTP请求的web服务器，由web服务器调用的本地二进制文件(例如，使用socket)，以及由本地二进制文件执行的外部命令来完成请求。

每个相互作用的固件组件(web服务器、后端应用程序和其他辅助程序)可以对共享的数据做出不同的假设，不一致性可能表现为安全漏洞。在固件样本的不同组件之间精确检测这些不安全的多二进制交互是具有挑战性的。孤立地考虑每个组件而不考虑内部数据流的程序分析方法会产生次优结果，因为它们(i)忽略了组件在二进制间通信过程中施加的有意义的约束，(ii)无法有效区分攻击者控制和非攻击者控制的输入源，以及(iii)可能只发现表面上的错误。

考虑一个接受用户凭证的web服务器，将其长度限制为16个字符，然后将它们传递给处理程序二进制(例如，通过环境变量)，该处理程序将它们复制到两个16字节长的缓冲区中。如果后一种二进制文件专门用于处理web服务器接收(和审查)的用户凭据，那么它可能会放弃长度检查的实现。在本例中，孤立地分析处理程序二进制可能会导致识别在实践中不可能触发的错误，并且安全性分析可能会产生大量误报，因为它必须假设二进制中的所有输入源都可能产生不受约束的攻击者控制的数据。这些误报需要由人工分析师进行检查，这代表了时间成本。由于分析人员检查、打补丁和测试固件样本所需的时间是不可忽略的，因此在实践中不构成安全威胁的二进制文件之间的受控交互应该被优先考虑。另一方面，仅考虑面向网络的二进制文件(即直接接受用户请求的二进制文件)的分析无法识别固件中更深层次和更复杂的错误。

因此，有效的固件分析必须考虑多个二进制文件，并对它们共享的数据进行推理。

不幸的是，大多数现有的程序分析工作一次只关注单个程序或模块[55]，[37]，[45]。虽然有些工作试图模拟嵌入式设备，从而同时分析所有组件，但目前的方法要么对固件样本施加严格的假设[11]，要么实现有限的成功率(即从13%[12]到21%[5])。其他方法[6]，[48]，[54]试图直接分析实际设备，但由于它们采用纯动态技术(例如，模糊测试)，它们可能无法发现更深层次和更复杂的漏洞[34]。

在本文中，我们介绍了KARONTE，这是一种新颖的静态分析方法，可以跟踪固件样本二进制文件中的数据流，以精确地发现安全漏洞。KARONTE基于二进制文件使用一组有限的进程间通信(IPC)范例进行通信的直觉，它利用这些范例中的共性来检测将用户输入引入固件示例的位置，并识别各种组件之间的交互。然后使用识别的交互来跟踪组件之间的数据流，并执行跨二进制污染分析。最后，使用传播的污点和约束来检测用户控制输入的不安全使用，这可能导致漏洞。

我们实现了KARONTE并使用两个数据集对其进行评估:53个当前版本固件样本和从相关工作中收集的899个样本[5]。我们利用以前的数据集来深入研究我们方法的每个阶段，并评估其有效性以发现错误。在我们的实验中，我们证明了我们的方法成功地识别了跨不同固件组件的数据流，正确地传播了污染信息。这使我们能够发现潜在的易受攻击的数据流，从而发现了46个零日漏洞，并重新发现了另外5个n天漏洞，证明了我们的方法在不同设计的复杂固件(即，单片嵌入式操作系统和嵌入式Linux发行版)上的有效性。毫无疑问，可靠的单二进制静态分析技术也可以发现这些漏洞，但它会产生大量的误报，从而使分析在现实世界中站不住脚。在我们比较KARONTE的多二进制分析方法和在单二进制模式下运行的相同分析(即禁用二进制间数据流跟踪)时，产生的警报数量从每个样本的平均2个增加到平均722个:KARONTE提供了两个数量级的警报减少和由此产生的低假阳性率。正如我们的评估中所示，我们估计验证由单二进制分析产生的所有警报可能需要安全分析师大约四个月的工作。另一方面，我们的原型生成的警报的验证累积时间大约为10小时。

最后，我们利用第二个更大的数据集来研究我们的工具的性能，显示其在不同大小和复杂性的固件样本上进行扩展的能力。

综上所述，我们做出了以下贡献:

- 我们介绍了静态分析技术的新组合来执行多二进制污染分析。为此，我们设计了一种新的技术，可以在多个二进制文件中精确地应用和传播污染信息。
- 我们提出KARONTE，一种新的静态分析方法来识别二进制文件之间的不安全交互。KARONTE从根本上减少了误报的数量，使现实世界的固件分析变得实用。
- 我们在53个真实固件样本上实现并评估了KARONTE原型，结果表明我们的工具可以成功地在多个二进制文件中传播污染信息，从而发现了46个未知(零日)bug，并产生了很少的误报。然后，我们利用899个固件样本的更大数据集来评估我们的工具的性能。
- 我们的工具得到的结果被另一所大学的独立研究人员彻底验证。

本着开放科学的精神，我们发布了我们的原型和docker映像的实现，以复制我们的工作环境: https://github:com/ucsb-seclab/karonte

## 2.背景
本节提供背景信息，以了解我们的方法的目标及其固有的挑战。

### A.物联网攻击者模型
物联网设备通过网络交换数据。这些数据可以直接来自用户(例如，通过web界面)，也可以间接来自受信任的远程服务(例如，云后端)。许多设备，特别是路由器、智能电表和许多低功耗设备，如智能灯泡和锁，都使用前一种模式。此外，最近的攻击表明，这些设备可以被聪明的远程攻击者利用，即使他们的通信被限制在一个封闭的本地网络中[23]。在这项工作中，我们考虑了直接通过本地网络或互联网与设备通信的基于网络的攻击者。然而，如第X节所示，KARONTE可以很容易地扩展到其他场景。

### B.固件复杂度
现代物联网设备的固件非常复杂，由多个组件组成。这些组件可以是不同的二进制文件(打包在嵌入式Linux发行版中)，也可以是不同的模块(编译成大型的单二进制嵌入式操作系统)(“blob固件”)。前一种类型的固件是目前最普遍的：一个大规模的实验分析了数以万计的固件样本，发现其中86%是基于linux的[11]。与其他基于linux的系统类似，基于linux的固件包含大量相互依赖的二进制文件。

嵌入式设备上固件的不同二进制文件(或组件)共享数据以执行设备的任务。在我们的攻击者模型下，这种交互是至关重要的，因为我们关注的是可能由攻击者从设备“外部”(即通过网络)输入触发的bug，但可能会影响直接面向网络的二进制文件以外的二进制文件。任何只关注这些面向网络的二进制文件的分析都会忽略其他组件中包含的错误[6]。另一方面，孤立地关注所有二进制文件的分析将产生不可接受的错误警报。

我们在以下基于真实固件示例的示例服务中演示了这一点。该服务由一个面向网络的web服务器(清单1)组成，该服务器执行CGI处理程序二进制文件(清单2)。当web服务器接收到用户请求时，它调用函数serve_request。然后，在解析请求(parse_URI)之后，web服务器执行处理程序，通过QUERY_STRING环境变量传递数据。处理程序二进制检索数据并将其传递给process_request。此函数包含一个bug:如果用户请求中的字段op的值大于128字节，则会发生缓冲区溢出。这种溢出是由攻击者控制的，代表了一个重大漏洞。

![](2020-SP-KARONTE-Detecting%20Insecure%20Multi-binary%20Interactions%20in%20Embedded%20Firmware.pdf/image-20231211095431700.png)

虽然这种特定的溢出将由只关注处理程序二进制的分析检测到，但任何单二进制分析都将检测到该程序中的两个漏洞。第二个问题是由LOG_PATH环境变量引起的log_dir缓冲区溢出。虽然这是一个合法的错误，但它的漏洞分类取决于LOG_PATH中数据的来源。如果攻击者无法控制这些数据，那么这个bug就不是漏洞，应该优先考虑真正的漏洞。理想情况下，每个警报都会被检查，每个bug都会被修复。不幸的是，这个目标在实践中是不可行的。虽然这个简单的例子有两个警报，揭示了一个漏洞，但我们的评估表明，对真实固件中的单个二进制文件进行静态分析可能会在每个设备上产生数千个警报，需要分析师数月的时间来处理。

为了使静态分析在二进制文件上可行，过滤掉无法由攻击者触发的错误的方法至关重要。KARONTE就是这样一种方法。它通过使用静态分析将生成(或设置)数据的函数连接到使用(或获取)数据的其他二进制文件中的函数，从而识别二进制文件之间的数据依赖关系，例如本例中的二进制文件。

在本文中，我们将上面示例中显示的程序交互称为多二进制交互。类似地，我们将涉及跨多个二进制文件的数据流的漏洞称为多二进制漏洞。最后，我们将产生数据的二进制(例如，清单1中的web服务器)称为setter二进制，将消费数据的二进制(例如，清单2中的处理程序二进制)称为getter二进制。

### C.物联网固件中的IPC
自动确定用户输入如何被引入嵌入式设备并通过嵌入式设备传播是一个悬而未决的问题[36]，[51]，[55]，并且容易出现令人沮丧的误报率[22]。然而，我们观察到，在实践中，进程通过一组有限的通信范式进行通信，称为进程间通信(IPC)范式。

IPC的实例是通过一个唯一的key(我们称之为数据key)来标识的，该key为通信中涉及的每个进程所知。由于这些信息必须在所有相关程序执行之前可用，因此通常硬编码在二进制文件本身中。例如，通过一个文件交换数据的两个二进制文件在传输数据之前必须知道文件名(即数据key)。

与公共IPC范例相关联的数据key可用于静态跟踪攻击者控制的二进制文件之间的信息流。下面，我们将描述在firmware中使用的最常见的IPC范例。

**文件**。进程可以通过文件共享数据。一个进程在给定的文件上写入数据，另一个进程读取和使用这些数据。数据键是文件本身的名称。

**共享内存**。进程可以共享内存区域。共享内存可以由文件系统上的文件支持，也可以是匿名的(如果两个进程是父子关系)。在前一种情况下，数据键由后备文件名表示，而在后一种情况下，由共享内存页的虚拟地址表示。

**环境变量**。进程可以通过环境变量共享数据。在本例中，数据键是环境变量名(例如QUERY_STRING)。

**套接字**。进程可以使用套接字与驻留在同一主机上的进程(具有文件路径的Unix域套接字)或驻留在不同主机上的进程(网络套接字)共享数据。套接字的端点(例如，IP地址和端口，或Unix域套接字的文件路径)表示数据key。

**命令行参数**。一个进程可以产生另一个进程，并通过命令行参数传递数据。数据键是被调用程序的名称。

我们将共享数据表示为元组(data_key, data)。

## 3.方法概述
KARONTE是一种执行二进制间数据流跟踪的方法，可以自动检测固件样本二进制文件之间的不安全交互，最终发现安全漏洞。虽然我们的系统专注于检测内存损坏和DoS漏洞，但它可以很容易地扩展，如第IX节所讨论的那样。KARONTE通过以下五个步骤分析固件样本(图1):

![](2020-SP-KARONTE-Detecting%20Insecure%20Multi-binary%20Interactions%20in%20Embedded%20Firmware.pdf/image-20231211103919956.png)

**固件预处理**。KARONTE的输入由一个固件样本(即整个固件映像)组成。作为第一步，KARONTE使用现成的固件解包工具binwalk[20]解包固件映像。

**边界二进制发现**。边界二进制发现模块分析未打包的固件示例，并自动检索将设备功能导出到外部世界的二进制文件集。这些边界二进制文件包含了接受来自外部源(例如网络)的用户请求所必需的逻辑。因此，它们表示攻击者控制的数据在固件本身中引入的点。对于每个边界二进制，该模块识别引用攻击者控制数据的程序点(第IV节)。

**二进制依赖图(BDG)恢复**。给定一组边界二进制文件，KARONTE构建一个二进制依赖图(Binary Dependency Graph, BDG)，这是一个有向图[49]，用于模拟处理攻击者控制数据的二进制文件之间的通信。通过利用通信范式查找器(CPF)模块的集合来迭代地恢复BDG，这些模块能够推断不同的进程间通信范式(第V节)。

**多二进制数据流分析**。给定BDG中的二进制b，我们利用静态污染引擎(参见第VI节)来跟踪数据如何通过二进制传播，并收集应用于此类数据的约束。然后，我们将数据及其约束传播到BDG中具有来自b的入站边的其他二进制文件(第VII节)。

**不安全交互检测**。最后，KARONTE确定了由攻击者控制的不安全数据流造成的安全问题，这些问题将报告以供进一步检查(第VIII节)。

KARONTE的新颖之处在于其二进制依赖图的创建及其跨二进制边界准确传播污染信息的能力，从而能够以有效的方式检测复杂的多二进制漏洞，并大大减少可能产生的误报数量。虽然KARONTE专注于二进制间的软件错误，但它也执行单二进制分析。

此外，虽然KARONTE检测跨固件样本二进制文件的数据流，但其通用设计允许KARONTE也可以推断单片嵌入式操作系统的不同模块的交互，只要这些模块之间存在分离(例如，它们在运行时代表不同的进程)，如第x节所示。最后，鉴于我们的攻击者模型(第II-A节)，我们假设边界二进制文件由面向网络的二进制文件表示(即，实现网络服务的二进制文件)。出于这个原因，我们可以互换使用边界二进制和面向网络二进制这两个术语。

## 4.边界二进制发现
KARONTE旨在检测网络上可能被攻击者利用的漏洞。为此，KARONTE首先在固件示例中识别导出网络服务的二进制文件集(即，面向网络的二进制文件)。我们观察到，面向网络的二进制文件是接收和解析用户提供的数据的固件样本的组件。因此，我们在固件样本中识别那些解析从网络套接字读取的数据的二进制文件。

根据Cojocar等人[8]的工作，我们利用三个特征来识别实现解析器的嵌入式系统中的函数:(i)基本块的数量(#bb)， (ii)分支的数量(例如，if-then-else，循环)(#br)，以及(iii)与内存比较一起使用的条件语句的数量(#cmp)。由于我们想要明确识别受输入影响的网络解析器，我们考虑了两个额外的特征:(iv)我们称为网络标记(#net)的度量，以及(v)我们称为连接标记(#conn)的标志。

网络标记特征编码解析函数处理网络消息的概率，它是通过识别函数代码中的每个内存比较来计算的，并将引用的内存位置与网络编码字符串的预设列表(例如，soap或HTTP)进行比较。我们将#net初始化为0，并在每次与代码中存在的网络编码字符串进行比较时增加它。

相反，连接标记标志指示是否在内存比较中使用从网络套接字读取的任何数据。将#conn初始化为0，如果在套接字读取操作和内存比较操作之间存在数据流，则将其设置为1。

我们将上述五个特征结合起来计算二进制b的解析分数$ps_b$如下:

![](2020-SP-KARONTE-Detecting%20Insecure%20Multi-binary%20Interactions%20in%20Embedded%20Firmware.pdf/image-20231211105358246.png)

其中设置每个常数ki以最大限度地提高解析检测能力(kbb = 0:5, KBR = 0:4, KCMP = 0:7[8])，而kn和kc分别促进引用网络编码关键字和解析网络数据的二进制文件的函数。最后两个常数的最优值在第X-B节中经验地找到。最后，psj是b的第j个函数的解析分数。请注意，为了突出显示受输入影响的网络解析器，我们将两个特征作为乘数引入。

由于所有二进制数据的得分都可能大于零，因此我们需要区分并分离“最显著”的得分。为此，我们利用了DBSCAN基于密度的聚类算法[15]，该算法将分数紧密聚集在一起的二进制文件分组。然后，我们选择包含固件样本中解析得分最高的二进制文件的集群，并将属于该集群的所有二进制文件作为面向网络的二进制文件的初始集。

最后，该模块实现的算法返回未打包的固件示例、已识别的面向网络的二进制文件集，以及包含与网络编码关键字进行内存比较的程序位置。这些内存比较表示攻击者控制的数据更有可能被引用的程序位置。

### 5.二进制依赖图
二进制依赖图模块检测属于固件样本的一组二进制文件或组件之间的数据依赖关系。此外，它还确定了数据如何从setter二进制数据传播到getter二进制数据。跨不同进程的数据传播不同于子例程调用/返回和程序库依赖分析期间的数据传输，因为这两者都是由控制流信息指导的。对于进程间交互，不存在可依赖的控制流传输，因为在使数据可用(例如，通过环境变量)之后，进程继续其执行。由于进程通常不访问其他进程的内存区域，传统的指向分析也是徒劳的。

KARONTE通过使用一组我们称为通信范式查找器(communication Paradigm finder, cpf)的模块，对各种进程间通信范式进行建模，从而解决了这些问题。KARONTE使用它们来构建一个图，称为二进制依赖图(或BDG)，它对固件样本中二进制文件之间的数据流信息进行编码。

### A.通信范式查找器
CPF提供必要的逻辑来检测和描述二进制文件用于共享数据的通信范式(例如，基于套接字的通信)的实例。为了实现这一目标，CPF考虑二进制和程序路径(即基本块序列)，并检查路径是否包含通过CPF所代表的通信范式共享数据所需的代码。如果是这样，它将通过以下特定于范例的功能收集通信范例的细节:

**数据key恢复**。CPF恢复引用二进制文件在相关通信范式下设置或检索的数据的数据键。

**流方向确定**。CPF标识访问收集的数据键所表示的数据的所有程序点。如果存在这样的程序点，则确定每个程序点在通信流中的角色(即setter或getter)。

二进制集放大。CPF标识固件示例中的其他二进制文件，这些二进制文件引用前面标识的任何数据键。这些二进制文件可能与当前正在考虑的二进制文件共享数据，因此计划进行进一步分析。

然后，我们将不同CPF收集的信息组合在一起，在二进制依赖图中创建边，恢复跨不同二进制文件的数据流。

每个CPF的细节取决于固件示例运行的操作系统(例如，Linux)。因此，为了保持操作系统的独立性，并在某些信息丢失(例如，固件blob)时推断进程间通信范式，KARONTE使用通用的独立于操作系统CPF，我们称之为语义CPF。这个CPF利用了这样一种直觉，即进程之间的任何通信都必须依赖于数据键，而数据键通常是硬编码到二进制文件(例如，硬编码的地址)。为此，Semantic CPF检测是否使用硬编码值来索引内存位置以访问一些感兴趣的数据(例如，攻击者控制的数据)。我们的KARONTE原型实现了环境、File、套接字和语义CPF(详见附录A)。

### B.构建BDG
KARONTE通过一个断开的循环有向图[49]来建模二进制文件之间的数据依赖关系，称为二进制依赖图(Binary Dependency Graph，简称BDG)。二值集B的一个BDG, G记为G=(B;E)，其中，E为有向边的集合。每个从$b_1 \in B$到$b_2 \in B$的有向边$e \in E$由一个三元组表示$e=([b_1, loc_1, cp_1],[b_2, loc_2, cp_2],k)$,这表明信息与数据相关联的密钥k(例如,一个环境变量名称)可以从二进制$b_1$的$loc_1$位置(例如,一个程序点包含到setenv函数的调用)通过$cp_1$的通信范式(如系统环境)，流动到二进制$b_2$的$loc_2$位置(例如,到getenv函数的调用)通过$cp_2$的通信范式。

恢复二进制依赖图的算法(算法1)首先考虑边界二进制文件发现模块收集的信息:(i)分析中未打包的固件样本(fw)， (ii)边界二进制文件(B)，以及(iii)执行内存比较的一组程序位置(int_locs)。然后，对于B中的每个二进制b，我们考虑int_locs中属于b的每个位置loc(函数get_locs)，并利用我们的污染分析引擎(第VI节)从包含loc(函数explore_paths)的函数开始引导符号路径探索。当分析到达loc时，我们污染被引用的内存位置buf，也就是说，将内存位置与网络编码关键字进行比较(函数get_buf并apply_taint)。

![](2020-SP-KARONTE-Detecting%20Insecure%20Multi-binary%20Interactions%20in%20Embedded%20Firmware.pdf/image-20231225213326205.png)

在路径探索的每个步骤中(即，对于每个访问的基本块)，我们调用每个我们的CPF模块，它们分析当前路径并使用污染信息(在路径探索期间由污染引擎传播)来检测二进制b是否共享一些受污染的数据d。如果一个CPFp匹配，即，它检测到被分析的二进制依赖于通信范式p来共享一些数据，我们利用CPFp来恢复正在使用的通信范式实例的所有细节。更准确地说，CPFp恢复用于通过p共享数据的数据key k，并推断对于k来说二进制文件的角色(即，setter或getter)(函数find_data_key_and_role)，并在固件示例中查找可能通过该通道通信的其他二进制文件(函数get_new_binaries)。然后将新发现的二进制文件添加到要分析的二进制文件的总体集合中。请注意，当计划分析任何这些新的二进制文件Bnew时，分析必须知道最初在哪里应用污染。换句话说，我们必须检测共享数据最初在这些新二进制文件中引入的位置。因此，对于每个新添加的二进制ba，CPFp还检索引用数据键k的程序点int_locsnew，并将它们添加到int_locs中。最后这两个操作由函数update_binaries执行。最后，对于每个已分析的二进制b，我们考虑在某个键k上匹配b的每个CPF (cp)，并使用cp检索k中b的角色(例如，setter)。然后，我们在b和任何其他对k具有相反角色的二进制文件(例如getter)之间创建一条边。

为了演示BDG算法，我们再次参考清单1。BDG算法首先考虑与网络编码关键字的内存比较(第3行)。在推断变量p在内存比较中使用之后，我们污染了它指向的内存位置，并从函数parse_URI(第1行)开始引导过程内污染分析探索在推断变量p在内存比较中使用之后，我们污染了它指向的内存位置，并引导过程内污染分析探索，从函数parse_URI(第1行)开始，并通过遵循程序的控制流传播污染。当污染探测到达execve函数调用(第13行)时，环境CPF检测到正在执行另一个二进制文件，并且使用setenv函数设置数据键QUERY_STRING。因此，环境CPF确定分析中的二进制是QUERY_STRING的setter。然后，Environment CPF扫描固件示例并查找依赖于相同数据键的其他二进制文件，并将它们添加到要分析的二进制文件集中。最后，对于每个新添加的二进制文件，Environment CPF检索引用数据键QUERY_STRING的代码位置(例如，调用函数getenv(“QUERY_STRING”))。

![](2020-SP-KARONTE-Detecting%20Insecure%20Multi-binary%20Interactions%20in%20Embedded%20Firmware.pdf/image-20231211095431700.png)

## 6.静态污点分析
KARONTE使用污染传播来检测多二进制漏洞。本节描述底层污染引擎的操作，下一节讨论KARONTE如何将污染引擎与前面描述的BDG结合起来实现这种检测。

KARONTE的污染引擎基于BootStomp[40]。给定一个污染源s(例如，一个返回不可信数据的函数)和一个程序点p，我们的污染引擎执行从p开始的符号路径探索，并且，每次遇到s时，污染引擎都会为从s接收数据的内存位置分配一个新的污染ID(或标记)。KARONTE的污染引擎在程序数据流之后传播污染信息，当内存位置被未污染的数据覆盖时，或者当其可能的值受到限制时(例如，由于语义等效于strlen和memcmp的函数)，它会对内存位置进行去污染(即，通过删除其污染标记)。与相关工作相比，我们的污染引擎有两个改进:(i)它包含了路径优先级策略，(ii)它引入了污染标签依赖关系的概念。

路径优先级策略通过优先考虑更有趣的路径来解决底层污染问题，当处理隐式控制流时，底层污染会影响基于路径探索的污染引擎[18]。在污染分析的范围内，如果感兴趣的变量在p1中受到污染，而在p2中没有受到污染，则路径p1被认为比路径p2更有趣。

考虑清单3中的示例，并假设变量user_input(第14行)指向受污染的数据。当调用函数parse时，变量start(第1行)别名user_input(即，它们指向相同的内存位置)，因此，它指向受污染的数据。函数parse可能包含无限多条路径:如果变量start由一个不受约束的符号表达式表示，那么总有一条可能的路径通过默认语句(第9行)到达while循环的头部(第3行)。在这些路径中，只有那些通过第一个case语句(第5行)传递的路径会将污染传播到函数外部。因此，不探索这些路径的分析将错误地确定user_input不能影响变量cmd(第15行)。

![](2020-SP-KARONTE-Detecting%20Insecure%20Multi-binary%20Interactions%20in%20Embedded%20Firmware.pdf/image-20231226092607251.png)

我们的路径优先级策略旨在评估函数内的路径，这些路径可能也会在函数外部传播污染(如路径经过清单3中的第一个case语句)。正如预期的那样，我们注意到面向网络的二进制文件包含各种消杀功能，这些功能可能导致刚才讨论的问题。在附录A中，我们描述了路径优先级特性的实现细节。

最后，在我们的污染引擎中，分析人员可以在具有不同标签的污染变量之间创建依赖关系(污染标签依赖关系)。在多标签污染跟踪系统中，跟踪这些依赖关系对于制定有效的去污染策略起着重要作用，从而缓解过度污染问题[41]。

为了演示这一点，请再次考虑清单3中的示例，并假设存在一个去污染策略，用于在变量显式地限制在一个值范围内时删除一个taint标记。首先，当get_user_input生成不受信任的数据(第14行)时，创建一个新的污点标记t1并将其分配给user_input。如果没有分析函数strlen(例如，它的代码不可用，或者没有遵循调用以保持整体分析的可处理性)，遵循多标记污染跟踪的语义[40]，变量n使用不同的标记t2被污染。当污染执行引擎到达if语句(第17行)时，遵循正在使用的去污染策略，通过删除标记t2来自动清除变量n。假设user_input(t1)的污染标记不同于n的标记(t2)，那么user_input并不是去污染的，并且对不安全的strcpy的调用(第19行)可能导致生成假阳性。出现这种行为是因为一些在语义上约束受污染数据的函数可能没有被分析(由于缺乏代码，或所使用的分析受到限制)。我们建议的解决方案是保持user_input的污染标签(即t1)依赖于n的污染标签(即t2)的信息，并且在n去污染时对user_input去污染。我们称污点标记t1依赖于污点标记t2，当移除t2(即，用t2标记去污染变量)会导致t1被移除。当然，污染标记t1可能依赖于多个污染标记。在这种情况下，如果t1所依赖的所有标签都被移除，t1也会被移除。我们的原型自动找到语义上等价的memcmp和strlen函数，并应用污染标签依赖(参见附录A)。

## 7.多二进制数据流分析
为了发现二进制文件之间的不安全交互并发现漏洞，我们需要恢复BDG中二进制文件的数据流细节。枚举BDG中所有可能的二进制间路径通常会导致路径爆炸问题[4]。






## 参考文献

