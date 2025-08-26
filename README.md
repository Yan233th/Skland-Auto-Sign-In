# Skland-Auto-Sign-In

森空岛自动签到脚本, 可搭配GitHub Actions等工具实现自动化

## Usage Instructions

tokens可存放于环境变量`USER_TOKENS`或`user_tokens.txt`中, 环境变量中用`;`分隔tokens, `user_tokens.txt`中用`\n`(换行)分隔  
登陆 [森空岛](https://www.skland.com/) 后获取token: https://web-api.skland.com/account/info/hg

推荐搭配 GitHub Actions 使用, Fork仓库并启用 `Scheduled Auto Sign In` Workflow, 将tokens以 `USER_TOKENS` 存于secrets中即可
> Repository Settings -> Secrets and variables -> Actions -> Repository secrets

Workflow可能会因缺失创建或编辑Release的权限而失败，若发生此情况，请开启Workflow的写权限
> Repository Settings -> Actions -> General -> Workflow permissions

## Disclaimer

纯练手用

## Acknowledgments

鉴权思路来源: [FancyCabbage/skyland-auto-sign](https://gitee.com/FancyCabbage/skyland-auto-sign)
