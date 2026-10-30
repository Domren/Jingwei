#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIL/Pillow兼容性修复模块
用于解决新版本Pillow库中ANTIALIAS被重命名的问题
"""

def fix_pil_antialias():
    """
    修复PIL库中ANTIALIAS兼容性问题
    在新版本的Pillow库中，ANTIALIAS已被重命名为LANCZOS
    """
    try:
        from PIL import Image
        
        # 检查是否存在ANTIALIAS属性
        if not hasattr(Image, 'ANTIALIAS'):
            # 如果不存在，则创建一个兼容性映射
            Image.ANTIALIAS = Image.LANCZOS  # 在新版本中，ANTIALIAS被重命名为LANCZOS
            print("已修复PIL.Image.ANTIALIAS兼容性问题")
    except ImportError:
        # 如果PIL不可用，则忽略
        pass
    except AttributeError:
        # 如果无法设置属性，则忽略
        pass

# 立即执行修复
fix_pil_antialias()