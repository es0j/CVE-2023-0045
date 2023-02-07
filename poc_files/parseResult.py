#!/usr/bin/python3
secret=[]
with open("result.txt") as f:
    for line in f:
        if "+" in line:
            secret.append("1")
        else:
            secret.append("0")
            
secret=secret[::-1]
print("Secret array: ", secret)
num = int("".join(str(x) for x in secret), 2)

print("The secret leaked is: ",num.to_bytes(18,'big')[::-1])