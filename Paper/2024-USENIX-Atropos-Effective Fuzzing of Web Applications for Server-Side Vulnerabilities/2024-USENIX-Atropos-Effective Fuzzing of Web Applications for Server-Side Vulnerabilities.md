---
title: 2024-USENIX-Atropos-Effective Fuzzing of Web Applications for Server-Side Vulnerabilities
date: 2023/12/15
categories:
  - 论文
tags:
  - 论文翻译
  - USENIX
---
# 2024-USENIX-Atropos-Effective Fuzzing of Web Applications for Server-Side Vulnerabilities
## 基本信息
题目：Atropos:有效模糊Web应用程序的服务器端漏洞

![](2024-USENIX-Atropos-Effective%20Fuzzing%20of%20Web%20Applications%20for%20Server-Side%20Vulnerabilities/image-20231215153458525.png)
## 摘要
服务器端web应用程序仍然主要使用PHP编程语言实现。即使在今天，基于php的web应用程序也受到许多不同类型的安全漏洞的困扰，从SQL注入到文件包含和远程代码执行。自动化安全测试方法通常侧重于静态分析和污染分析。这些方法高度依赖于PHP语言的准确建模，经常会出现(可能很多)误报。有趣的是，动态测试技术(如模糊测试)并没有在web应用程序测试中获得认可，尽管它们避免了这些常见的缺陷，并迅速被其他领域采用，例如，用于测试用C/ c++编写的本地应用程序。

在本文中，我们提出了ATROPOS，这是一种基于快照的反馈驱动模糊测试方法，专为基于php的web应用程序量身定制。我们的方法考虑了与web应用程序相关的挑战，例如维护会话状态和生成高度结构化的输入。此外，我们提出了一种反馈机制来自动推断web应用程序使用的键值结构。结合了八个新的漏洞预言器，每个涵盖了服务器端web应用程序中的常见漏洞类别，ATROPOS是有效和高效模糊web应用程序的第一种方法。我们的评估表明，在web应用程序测试中，ATROPOS的性能明显优于当前的技术水平。特别是，它发现的bug平均至少多出32%，而不会在不同的测试套件上报告一个误报。在分析真实世界的web应用程序时，我们确定了七个以前未知的漏洞，这些漏洞甚至可以被未经身份验证的用户利用。

## 1.引言
我们每天与之交互和依赖的web应用程序的数量在不断增长。77.6%的访问量最大的前1000万个网站仍然依赖PHP作为其服务器端应用程序的语言[62]。突出的例子包括维基百科、Etsy、WordPress、百度和Tumblr。鉴于PHP语言的广泛采用和持续流行，安全测试对于尽早识别潜在漏洞至关重要。

考虑到web应用程序的典型规模，手动源代码审计被证明是不切实际的。相反，最先进的方法通常依赖于静态分析技术[6,12,13,15,21]。通过准确地对PHP语言(特别是其内置函数)建模，并应用基于污点分析的方法，这些工具旨在识别从SQL注入到文件包含和远程代码执行的各种漏洞。尽管尽了一切努力忠实地对PHP语言进行建模，但现有的方法经常会出现(潜在的)误报。我们从经验上发现，这一观察结果仍然适用于现代方法(见5.2节)。值得注意的是，这个问题并不是PHP特有的，而是困扰着大多数静态分析工作[30,54]。大量的误报会适得其反，误导开发人员忽略实际的发现或浪费时间去寻找不存在的漏洞[24]。此外，静态分析通常不适合有效地生成帮助开发人员调试手头问题的测试用例[7]。

我们可以探索其他方法，而不是通过提高模型的准确性来避免误报。在测试本地应用程序时，一种发现故障的动态方法最近被证明特别有效:反馈驱动的模糊测试[4,16,20,67]。该方法提供了一种简单但快速的方法，用于针对目标程序测试各种(略有变化的)输入，并发现导致实际程序错误的输入。崩溃输入为开发人员提供了允许再现性和调试辅助的原语。

直观地看，模糊web应用程序听起来像是一种很有前途的方法。不幸的是，现代的fuzzers是针对特定类型的程序进行优化的，并且依赖于一些在web应用程序环境中不可用的属性。首先，它们的目标暴露了一个相对简单的接口(例如，标准输入或文件)，而web应用程序期望来自web服务器的输入，而web服务器又通过HTTP从web浏览器接收其输入。其次，典型的模糊目标不保持广泛的状态，并且可以通过简单地重新创建进程(这有助于模糊器的主要优势，它们的性能)来重置，例如，使用fork()。相反，web应用程序维护大量的状态，因为需要考虑web服务器、浏览器、会话、数据库和类似的方面。第三，标准的模糊测试目标在面向字节流的输入上操作，即，翻转比特和字节通常能成功地探索新的程序行为。相反，web应用程序是面向文本的，并且期望高度结构化的输入，通常包含开发人员定义的标识符。这些挑战使得传统的模糊测试方法在测试web应用程序时效率低下。更糟糕的是，fuzzers通常无法检测到何时触发了服务器端故障，因为它们只检查由内存访问违规引起的崩溃。但是，典型的web应用程序错误，如SQL注入、服务器端请求伪造(SSRF)或命令注入，不会使解释器崩溃。因此，即使fuzzer成功地触发了一个bug，它也不会识别它。

虽然在以前的工作中已经提出了一些web模糊测试方法，但它们未能解决所概述的挑战并且范围有限。WEBFUZZ[46]使用覆盖引导反馈，但只能检测客户端存储和反射的跨站点脚本(XSS)漏洞。类似地，CEFUZZ[69]仅限于远程代码执行和命令注入漏洞。这两种工具都不是直接模糊web应用程序，而是将HTTP请求发送到web服务器，由web服务器将请求转发给实际的web应用程序。几乎所有专注于动态测试web应用程序的工具都存在这种性能限制，包括WFUZZ等行业中使用的工具[31]。这个工具是一个先进的黑盒模糊器，能够发送和变异由人类领域专家指定的有效载荷。然而，它不是完全自动化的，缺乏对web应用程序维护的状态的感知，无法访问覆盖信息，并且通常没有服务器端漏洞的错误预测。与我们的工作同时，Trickel等人提出了WITCHER[58]，这是一种覆盖引导的模糊器，它实现了故障升级来检测SQL和命令注入漏洞。与其他灰盒模糊器类似，通过跟踪代码覆盖率来探索状态空间。对web应用程序的输出进行分析，以指导突变过程。然而，他们的方法仅限于两种类型的漏洞。

在这项工作中，我们提出了一种模糊测试方法，能够有效地测试web应用程序的不同类型的安全漏洞。我们的方法是专门来解释web应用程序的有状态特性而设计的通过使用快照。此外，我们提出了一种针对web应用程序的新颖反馈机制，允许我们的模糊器生成输入，绕过被测试web应用程序的浅层解析阶段，并有效地探索更深的程序部分。最后，我们介绍了八个新的错误预言器，每个都能够检测特定类别的服务器端PHP web应用程序错误。我们在一个名为ATROPOS的工具中实现了所提出方法的原型。评估表明，我们的动态方法明显优于静态分析方法:我们比性能最好的静态分析方法多发现32%的bug，同时在测试套件上报告零误报。在覆盖率方面，与WEBFUZZ和WFUZZ相比，我们平均覆盖了50%到230%的代码。综上所述，我们的主要贡献如下:

- 我们提出了ATROPOS，一种新的基于快照的反馈引导模糊测试方法，可以检测到八种类型的服务器端漏洞。
- 我们引入了一种新的反馈机制，直接从解释器中提取相关的运行时信息，通知随机变异体。正如我们的评估所显示的，这种方法可以实现比最先进的web应用程序模糊器更深的代码覆盖。
- 我们提出了八个新的错误预言器，可以有效地检测不同类型的服务器端漏洞，具有高检出率和很少的误报。此外，我们的方法不需要重量级的程序分析技术或复杂的仪器。

为了促进这一领域的进一步研究，我们在 https://github.com/cispa-syssec/atropos-legacy 上开源了ATROPOS的实现。该工作的扩展版本可作为技术报告[19]。

## 2.挑战
传统的模糊测试方法[3,8,16,20,65,67]已被证明对编译为本机二进制文件的语言有效，但不能直接适用于用PHP等解释性语言编写的服务器端web应用程序。特别是，我们确定了必须解决的三个主要挑战，以实现此类应用的高效和有效的模糊测试。

### 2.1 挑战1：复杂的接口
第一个挑战是服务器端web应用程序的复杂接口。我们需要复制web服务器为执行目标应用程序(即通过web浏览器访问的web应用程序)的解释器提供的环境，而不是像大多数本机二进制文件那样通过stdin或文件传递输入流。更具体地说，我们需要用一个直接与解释器通信的代理来取代web浏览器和HTTP web服务器，以减少不必要的开销。

一旦fuzzer可以将输入传递给web应用程序，它就需要为目标应用程序逻辑生成有意义的输入。接口的完整规范通常是不可用的，因此我们不能使用基于语法的模糊测试方法。类似地，由传统模糊测试方法生成的随机字节序列不太可能匹配web应用程序的输入，因此在早期解析阶段被拒绝。通常，web应用程序使用由开发人员设置的语义复杂的标识符。例如，当提交表单时，每个字段被分配一个由开发人员设置的字符串描述符(例如，password)。因此，这些描述符具有人类可以使用的语义含义，但妨碍了传统的模糊测试方法:为了传递此表单，模糊测试器必须生成字符串password=value，其中password是与表单关联的正确标识符，而value必须是此字段的有效值。这种语义令牌(以键值对的形式)不仅用于从表单中检索数据，还用于会话属性(例如，cookie)、URL参数或发送到REST api的JSON输入。值得注意的是，这个问题是魔术字节问题[4,8,42]的一种形式，其中fuzzer必须将特定的字节设置为特定的值才能通过检查。先前的研究提出了两种常见的解决方案:在模糊测试过程开始之前生成一个字典，或者使用LAF-INTEL-style的插桩[26]，该插桩甚至可以对部分解提供反馈，即输入“passw”将给出正反馈，表明模糊测试器正在接近正确的解。虽然这两种解决方案都很有用，但它们仅限于静态字符串，并且在运行时生成的字符串会失败。第二种解决方案的另一个常见障碍是为每次比较生成的中间垫脚石的数量(即，添加到语料库的输入)，对于具有许多此类比较的大型应用程序，这可能会压倒种子调度器。

### 2.2 挑战2：有状态的环境
现代web应用程序维护用户会话的扩展状态。通常，首先要对用户进行身份验证，以访问受保护的或特定于用户的资源。此外，web应用程序严重依赖数据库或持久存储来维护状态。这导致了两个问题:首先，状态分散在许多组件中，我们必须考虑到这一点。其次，状态的持久性会影响任何后续的执行(例如，删除文件或数据库条目将阻止未来的输入访问它)。

处理状态问题有两种方法。幼稚的方法是忽略大多数与web应用程序交互的状态，例如，在数据库中创建一个新条目。对于影响以后运行并且难以恢复的关键操作(例如，注销或删除数据)，人工领域专家必须识别适当的代码并将其放在块列表中。WEBFUZZ使用了这种方法[46]。然而，这需要一个人类专家，并且不允许测试web应用程序的完整功能。此外，被忽视的交互可能会默默地阻碍模糊测试的进展。处理状态的第二种方法是跟踪所有更改(例如，向数据库添加)并实现特殊逻辑以最终恢复所有更改(例如，通过从数据库中删除新数据)。然而，对每个输入都这样做是一个潜在的昂贵过程。

### 2.3 挑战3：Bug预言
与测试内存不安全程序的常见模糊测试方法不同，PHP或JavaScript等解释性语言中的应用程序错误通常不会表现为内存安全违规，因此无法使用依赖于崩溃信号的标准错误预测器观察到。相反，以下8个错误类代表了PHP的典型安全挑战:

1) **SQL注入**:当在SQL查询中使用未消毒的输入时，这种错误类就会发生，允许攻击者执行任意SQL命令(例如，提取或修改数据库中的敏感信息)[39]。
2) **远程代码执行**:允许攻击者注入和执行任意PHP代码的漏洞;例如，当攻击者控制eval()的输入时就会发生这种情况[34]。
3) **远程命令执行**:也称为命令注入，这使攻击者能够在服务器上执行任意shell命令[35]。
4) **本地和远程文件包含**:为了包含另一个文件(例如，一个模块)，PHP提供了多个指令。本地或远程文件包含漏洞允许攻击者将任意本地文件或远程资源解析为PHP代码并执行，从而获得远程代码执行[11]。
5) **PHP对象注入**:PHP数据和对象可以通过serialize()转换为字节流，并通过unserialize()转换回来。如果web应用程序允许用户操作以后一个函数结束的字节流，则可以注入任意PHP对象。这就引入了各种其他漏洞，如SQL注入或远程代码执行[13,36,41]。
6) **服务器端请求伪造(SSRF)**: PHP提供了许多函数来访问远程资源，例如，查询REST API。获得用于访问这些资源的目的地的控制允许攻击者以web服务器的名义伪造请求。这允许绕过通常将服务器的专用网络与Internet隔离的防火墙等对策[37]。
7) **任意文件读写**:这些漏洞使攻击者能够在web服务器上读取或写入任意文件。
8) **文件上传**:许多web应用程序允许用户上传文件，例如，设置头像。然而，如果上传的文件(name)没有经过适当的清理，或者没有根据允许列表进行检查，则可能会上传潜在的恶意文件，这可能最终导致任意代码的执行(例如，通过上传PHP文件)[40]。

总之，web应用程序对传统的模糊测试方法来说是一个挑战，因为它们展示了一个复杂的界面，维护了一个广泛的状态，并且包含了传统的错误预言器无法检测到的软件错误。

## 3.设计
为了解决上述挑战，我们提出了ATROPOS的设计，这是一种用于测试web应用程序的新型模糊测试方法。我们关注的是基于php的web应用程序，但下面描述的技术也可以应用于其他类型的web框架。

### 3.1 架构概述
图1提供了ATROPOS体系结构的高级概述。一般来说，我们希望模糊一个由多个进程组成的web应用程序，即PHP解释器执行应用程序并与数据库、文件系统和潜在的其他组件进行交互。所有组件都高度依赖于它们的状态和环境，这就要求它们在一个孤立的系统(例如，虚拟机)中运行，以允许拍摄快照和重置状态。

![](2024-USENIX-Atropos-Effective%20Fuzzing%20of%20Web%20Applications%20for%20Server-Side%20Vulnerabilities/image-20231215161729838.png)

为了指导模糊测试过程，我们安装了PHP解释器来提供覆盖率反馈和自省功能。在内部，ATROPOS的工作原理类似于afl++等fuzzers[16]。事实上，ATROPOS使用与afl++相同的算法，称为explore[16]，用于种子选择和优先级排序。我们还包括其典型的面向字节的突变，例如位翻转。为了实现web应用程序的模糊测试，我们提出了一些改变，以解决web环境中的独特挑战。首先，由于web应用程序可以由多个PHP文件组成(所有这些文件都是模糊器事先知道的)，因此atropos在每次模糊迭代中随机选择一个。其次，每个模糊测试输入可以包含多个请求，允许模糊测试器在一个模糊测试迭代中依次运行两个或多个文件。由于对web应用程序的每个请求都是高度结构化的，因此ATROPOS具有一个自定义的mutator，反映了输入的键值导向结构，并在VM中执行目标和所有相关进程，因此它可以通过快速的全系统快照机制有效地恢复整个环境。此外，我们还针对服务器端漏洞设计了8个定制的bug预言器。ATROPOS明确地避免了昂贵的操作，如静态分析或污染分析，以保持高吞吐量，其错误预测器旨在保持低误报的数量。

### 3.2 先进的反馈机制
web应用程序通常由解释器(例如PHP解释器)执行，解释器从web服务器接收输入，而web服务器又从web浏览器接收输入。为了减少开销和提高测试性能，我们用FastCGI[43]接口代替了web浏览器和web服务器，作为一种更直接的通信方式。然而，PHP web应用程序仍然需要高度结构化的输入，因为它们大量使用键值对形式的语义令牌。传统的模糊测试工具，如AFL[67]，将随机突变应用于输入。相比之下，我们的设计是基于web应用程序对输入的感知表示，并涉及许多技术来生成有意义的键值对，例如，我们识别web应用程序期望的输入结构的部分，并将它们以字典的形式提供给模糊器，该字典可用于精确地改变特定的键和值。以下技术构成了我们的PHP web应用程序特定的高级反馈机制，补充了fuzzer的覆盖率反馈。

#### 3.2.1 推断特定应用的键
当web应用程序接收到请求时，可以被web应用程序访问的几个全局映射(例如，\$\_GET， \$\_POST或\$\_SERVER)将根据web浏览器的请求填充。因此，我们的fuzzer还必须填充web应用程序访问的键。这些通常是复杂的语义标记，模糊器不太可能随机生成。为了解决这个问题，我们利用了对执行环境的完全控制:ATROPOS与PHP解释器访问这些全局映射的过程挂钩。当它观察到一个新的访问时，钩子将访问的键作为反馈提供给fuzzer。这允许ATROPOS为下一次模糊迭代设置期望的键。例如，考虑图1中的输入➊:在处理初始的随机模糊输入abc=xyz时，web应用程序访问key page，我们的钩子将其作为缺失的键报告给模糊器。这样，ATROPOS就可以在我们后续的请求➋中设置密钥。值得注意的是，这适用于所有键，甚至是那些在运行时动态生成的键。

### 3.2.2 推断期望的值
为了测试应用程序的更深层部分，fuzzer不仅需要正确的键，还需要一个特定的值，例如，page=login。我们的fuzzer一般可以推断web应用程序在运行时使用的所有值。传统上，这可以通过几种方式完成:(1)污染分析，(2)符号执行，或(3)基于启发式的技术。前两种技术存在状态爆炸和大量开销问题，实现成本也相当高。因此，在我们的设计中，我们使用了类似于输入到状态对应的启发式方法[4]，但针对web应用程序领域进行了定制。直观的洞察力是，在许多情况下(部分)输入直接与特定值进行比较。由于web应用程序的输入是基于字符串的，我们可以钩住PHP解释器中的所有字符串比较函数，例如zend_string_equal_val。当ATROPOS遇到字符串比较时，钩子将信息作为反馈传递给fuzzer。然后，ATROPOS可以用预期值随机替换出现的“错误”值。在图1中，web应用程序第3行中的if子句将我们的随机输入xyz与期望值login进行比较。接收到正确的值作为反馈，模糊器可以用login替换xyz，从而在第三个模糊迭代(oo)中发送有效的输入page=login，以解锁应用程序逻辑的更深层部分。

我们强调，这个推理过程不仅限于全字符串比较，还包括部分比较。根据经验，我们观察到，当解析本身在PHP中实现时，ATROPOS能够操纵JSON等高度结构化的输入值，甚至可以从头生成有效的HTTP头，从而通过这些高级反馈机制提供相关信息。值得注意的是，这种方法甚至适用于CSRF令牌，因为ATROPOS使用完整的系统快照，因此CSRF令牌是确定的。

虽然输入到状态的对应方法在实践中似乎工作得很好，但是对输入进行更极端的更改，例如加密散列和base64编码，确实具有挑战性。然而，对于一般的模糊测试来说，这是事实[4,42]。例如，当输入在与SHA256哈希进行比较之前进行哈希时，ATROPOS不可能解决此检查。虽然添加对BASE64等编码的支持当然是可能的，但我们还没有看到在实践中需要这样做。不那么极端的输入转换，如STRTOUPPER或STR_REPLACE应该是可解决的，因为结果运行时字符串被提取并在输入生成期间使用。

ATROPOS使用这些键值对的抽象表示来进行模糊测试，在最后一步将其输入到PHP时，仅将其转换为a=b&c=d形式的HTTP(或FastCGI)输入。我们强调，困难不在于生成和维护HTTP输入格式，而在于派生正确的键值对。

...

### 3.4 内存破坏之外的Bug预言
...

**新的bug预言器**。总的来说，我们针对2.3节中讨论的八种服务器端web应用程序漏洞提出了自定义的漏洞预言器。特别是，它们的不同之处在于如何识别可疑的功能行为以及如何将模糊输入跟踪到易受攻击的接收器。
1) **SQL注入**。如果在处理包含模糊控制输入的SQL查询时，输入导致语法错误，则此错误oracle报告一个漏洞。直观地说，只有未经处理的输入才能够通过更改查询来破坏SQL查询的语法，从而避免预期的约束(引号等)。
2) **远程代码执行**。如果模糊器控制的输入在编译动态PHP代码时引发语法错误，例如，在调用eval()期间，oracle会报告一个漏洞。与SQL注入oracle类似，如果攻击者控制的输入碰巧被解释，则很有可能发生语法错误，因为大多数随机输入都是无效的PHP代码。清单3b提供了eval()函数的一个简单示例。此外，ATROPOS注入有效的PHP代码，在执行时报告漏洞，因为攻击者不应该能够在web应用程序的上下文中运行自定义代码。
3) **远程命令执行**。识别远程命令执行(如清单3c所示)更加困难，因为我们没有显式的错误消息。相反，这个oracle监视执行不存在的二进制文件的尝试，如果二进制文件名在攻击者的控制之下，就会出现这种情况。此外，fuzzer试图注入一个命令，试图执行我们放置在VM中的自定义二进制文件，该命令会自动触发此oracle。
4) **本地和远程文件包含**。如果调用与文件相关的函数(如include()或require())导致文件不存在的错误，而文件路径包含由fuzzer控制的输入，则报告文件包含漏洞(示例如清单3d所示)。在某些情况下，应用程序在包含该文件之前检查该文件是否存在。为了识别文件包含漏洞，即使存在这样的检查来保护它们，ATROPOS偶尔也会向文件插入一个路径，该路径在包含文件时报告文件包含漏洞。
5) **PHP对象注入**。如果攻击者控制的输入以反序列化调用结束(unserialize()，参见清单3e)，则报告对象注入漏洞。由于序列化的数据是结构化的输入，解析错误可以用来检测可疑行为，类似于SQL注入oracle。
6) **服务器端请求伪造**。如果资源请求可以指向私有地址范围(例如http://192.168.0.1)，同时还包含fuzzer控制的输入，则该oracle报告一个SSRF漏洞(例如，通过控制调用file_get_contents()的主机，参见清单3f)。
7) **任意文件读写**。由于很难确定某些观察到的文件操作是否为恶意操作，因此我们保守地将此错误oracle限制为PHP文件。如果web应用程序试图读取、写入、删除或重命名PHP文件，同时在文件名中包含fuzzercontrolled输入，则触发此oracle(参见清单3)。此外，ATROPOS尝试提供一个金丝雀PHP文件，该文件触发oracle，并根据应用于它的文件操作报告错误。
8) **文件上传**。此类别还高度依赖于上下文:上传某些文件可能对一个应用程序是允许的，但对另一个应用程序可能构成漏洞。我们认为只有上传PHP文件(即，以.PHP结尾的文件)是一个安全问题，因为这是最不模棱两可的违反。如果通过相应的挂钩函数上传PHP文件成功(例如清单3h中的move_uploaded_file())，我们认为这个bug被触发了。

总之，这些自定义的错误预言器对特定的服务器端web应用程序漏洞很敏感。将这些错误预言与我们的fuzzer推断web应用程序使用的键和值的能力以及基于快照的设计相结合，我们可以有效地模糊web应用程序。

## 4.实现
我们在一个名为ATROPOS的原型中实现了我们的设计，用了大约3700行C、Python和Nim代码。ATROPOS分为两个组件:(1)前端，它生成输入并决定语料库中的哪个种子下一步要模糊化，(2)后端，它在虚拟机中运行web应用程序。两个组件都通过共享内存和超级调用交换信息。此外，ATROPOS的实现围绕着主要的模糊测试执行循环，它需要(1)生成和改变输入，(2)接收关于web应用程序的哪些代码区域被执行的反馈，(3)报告任何漏洞，以及(4)将环境恢复到原始状态。

**一般设置**。在启动模糊测试之前，必须安装web应用程序和所有组件。我们使用Docker容器来准备环境以简化此过程。这允许手动准备，例如以用户身份登录到目标web应用程序，以便为fuzzer提供一组初始功能。

**生成输入**。与二进制目标不同，PHP web应用程序期望输入是键值对的形式。ATROPOS前端的主要功能是作为afl++的自定义mutator实现的，其中键和值输入可以单独突变，使用我们在3.2节中解释的高级反馈方法。在执行每个输入之前，将其转换为FastCGI参数并传递给后端VM中的代理。

如前所述，web应用程序很少直接访问这些输入。相反，PHP解释器将这些参数转换为由键值对组成的易于访问的关联数组。我们可以模糊处理的外部输入源主要有四种类型:(1)\$\_GET超全局变量包含通过URL传递的所有输入，(2)\$\_POST主要包含通过HTML表单发送的输入，(3)\$\_COOKIE允许访问cookie， (4) \$\_SERVER提供各种信息，例如主机名，user-agent等。

...