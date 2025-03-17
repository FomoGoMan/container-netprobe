
# 运行测试 

## 1.build test image
```bash
cd ebpf/example/docker/image/
docker build -t example .
```

## 2.start test docker container
```bash
docker run -d --name example --network host  --user 1000:1000 example
```

## 3.build traffic monitor
```bash
cd cmd/ # 项目根目录下的cmd
go build ./
./cmd \<container id\>
```

> Note: Only support Linux system