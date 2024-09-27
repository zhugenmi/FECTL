#include<stdio.h>
int main() {
    // 指定文件路径和名称
    const char *filepath = "/dev/systat";

    // 使用"w"模式打开文件，如果文件不存在则创建
    FILE *file = fopen(filepath, "w+");

    // 检查文件是否成功打开
    if (file == NULL) {
        printf("无法创建文件 %s\n", filepath);
        return 1; // 返回错误代码
    }

    // 在这里可以向文件写入内容，例如：
    fprintf(file, "Hello, World!\n");

    // 关闭文件
    fclose(file);

    printf("文件 %s 已创建。\n", filepath);

    return 0; // 程序成功结束
}
