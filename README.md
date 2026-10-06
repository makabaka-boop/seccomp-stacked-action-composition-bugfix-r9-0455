

## 合并过滤器
`python3 seccomp-tool/tools/seccompcompose left.json right.json output.json` 产生含 base64 过滤器原始字节、逐条指令和来源映射的单一结果包。
等价于在子进程中先装左侧再装右侧：两者都允许才放行，KILL 优先于 ERRNO，ERRNO 优先于 ALLOW；同为 ERRNO 时右侧的数据优先。
两侧分别保持原首匹配和默认动作。只接受同架构；x86_64 的架构与 x32 门、64 位参数比较、长跳转及全部路径返回限制保留。
来源须能指回原策略规则、默认或架构门，并标出真正决定返回的侧。结果不得超过内核指令上限，无效或过大的组合整体拒绝且保留原输出。
Linux 合并语义依据 https://docs.kernel.org/userspace-api/seccomp_filter.html；原单策略命令和 C 探针继续可用。
