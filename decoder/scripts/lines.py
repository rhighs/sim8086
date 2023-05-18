import sys
for i in range(len(sys.argv[1:])):
    with open(sys.argv[1:][i], "r") as file:
        print(file.read().split("\n")[i])
