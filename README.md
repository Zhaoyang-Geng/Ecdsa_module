# Ecdsa_module

## t.mbox.gz
内核patch，可以通过
```bash
# 解压缩
$ gunzip t.mbox.gz
# 应用
$ git am t.mbox -3
# 处理 Patch is empty 问题
$ git am --skip
```

## md5
netfilter及添加optional字段的内核模块。处理数据包中的payload，计算其md5值后写入optional字段中。
使用``$ make``编译，之后使用``$ insmod md5_option`` 插入内核模块。
最后可以通过wireshark或其他抓包工具查看插入optional字段的数据包。

## ecdsa_akcipher
验证patch，使用固定密钥完成签名和验证。
使用``$ make``编译，之后使用``$ ecdsa_kernel_module`` 插入内核模块。
可以通过查看日志来观察是否完成签名或验证
