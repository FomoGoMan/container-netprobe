FROM docker.io/centos:7

# 安装新内核
RUN rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org && \
    rpm -Uvh https://www.elrepo.org/elrepo-release-7.el7.elrepo.noarch.rpm && \
    yum --enablerepo=elrepo-kernel install kernel-lt -y && \
    yum install -y clang llvm elfutils-libelf-devel

# 编译 eBPF 程序
WORKDIR /app
COPY . .
RUN go generate ./traffic && \
    CGO_ENABLED=1 GOOS=linux go build -o monitor

CMD ["/app/monitor"]