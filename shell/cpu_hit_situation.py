import random

# 设置矩阵大小
N = 10000

# 初始化矩阵
matrix = [[random.randint(0, 9) for j in range(N)] for i in range(N)]

# 计算矩阵元素的和
sum = 0
for i in range(N):
    for j in range(N):
        sum += matrix[i][j]

print("Sum of matrix elements: {}".format(sum))
