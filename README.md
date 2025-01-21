# Skland-Auto-Sign-In

森空岛自动签到脚本，可搭配GitHub Actions等工具实现自动化

## Usage Instructions

tokens可存放于环境变量`USER_TOKENS`或`user_tokens.txt`中, 环境变量中用`;`分隔tokens, `user_tokens.txt`中用`\n`(换行)分隔\
获取森空岛token: https://web-api.skland.com/account/info/hg

推荐搭配GitHub Actions使用，tokens以`USER_TOKENS`存于secrets中即可
> Repository Settings -> Secrets and variables -> Actions -> Repository secrets

## Disclaimer

纯练手用

## Acknowledgments

鉴权思路来源: https://gitee.com/FancyCabbage/skyland-auto-sign/
