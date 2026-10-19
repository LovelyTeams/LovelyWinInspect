## 📥 下载与使用

1. 下载下方附件 `LovelyWinInspect.exe`
2. 右键 **以管理员身份运行**（部分日志与策略需要管理员权限）
3. 程序会自动开始排查，完成后在左侧切换模块查看结果

系统要求：Windows 10 1703 及以上 / Windows Server 2019 及以上（x64）。

## 🔐 文件校验

```
SHA256  {{SHA256}}  LovelyWinInspect.exe
```

PowerShell 校验：`Get-FileHash .\LovelyWinInspect.exe -Algorithm SHA256`

## ⚠️ 说明

- 程序未做代码签名，并且会读取大量系统敏感位置，部分杀毒软件可能误报，可将其加入信任
- 仅用于授权范围内的安全检查与应急响应

{{COMPARE}}许可证：[AGPL-3.0](https://github.com/{{REPO}}/blob/main/LICENSE)
