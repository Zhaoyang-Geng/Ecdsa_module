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

## ecdsa_akcipher
验证patch，使用固定密钥完成签名和验证。

