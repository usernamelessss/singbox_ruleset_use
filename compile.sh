#!/bin/bash

# 设置基础目录
base_dir="rule"
suffix=".json"
# 遍历 rule 文件夹下的每个子文件夹
for dir in "$base_dir"/*/; do
    # 获取 rule 规则总目录下的所有子文件夹
    # 遍历子文件夹
    for file in "$dir"/*"$suffix"; do
        if [[  -f "$file"  ]] ; then
          # 获取文件名(含后缀)
          source_file=$(basename "$file")
          echo "找到文件 ==> $dir$source_file"
          # 只获取文件名(不含后缀)用于拼接输出文件名
          file_name=${source_file%.*}
          output_file="$dir$file_name.srs"
          # 执行 sing-box 命令编译源文件
          sing-box rule-set compile --output "$output_file" "$dir$source_file"
          echo "👉 执行 sing-box 命令: $dir$source_file ==> $output_file"
      fi
        echo "未找到文件: $dir$source_file"
    done
done
