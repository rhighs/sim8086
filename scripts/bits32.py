import sys
with open(sys.argv[1], 'rb') as file:
    bytes = file.read()
    i = 0
    for b in bytes:
        if i == 4:
            i = 0
            print("")
        i+=1
        for j in reversed(range(0, 8)):
            print("1" if (b >> j) & 0x1 == 1 else "0", end="")
        print(" ", end="")
    print("")
