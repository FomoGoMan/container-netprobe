# 环境要求
1. linux kernel >= 5.15
2. `docker version --format '{{.Server.APIVersion}}'` 需要 >= 1.48 ,
> 更新命令 `sudo apt-get update && sudo apt-get install docker-ce`


# 示例
- 说明：改示例使用程序A 拉起容器镜像 B后，在程序A中统计B的所有产生的出口和入口流量总和，目前实现没有区ICMP， TCP等流量类型，所以捕获的流量可能比实际的流量略大

- 运行
1.进入`/example/monitor`目录，`go run main.go`