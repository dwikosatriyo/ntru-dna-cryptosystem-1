import sys,time

def sqsort1(xxs):
    if len(xxs) == 1 or len(xxs) == 0:
        return xxs
    x = xxs[0]
    xs = xxs[1 :]
    l = []
    g = []
    for x2 in xs:
        if x2 < x:
            l.append(x2)
        if x2 >= x:
            g.append(x2)
    return sqsort1(l) + [x] + sqsort1(g)

def sqsort2(xxs):
    left, right = [], []
    while True:
        if len(xxs) == 1 or len(xxs) == 0:
            return left + xxs + right
        x = xxs[0]
        xs = xxs[1 :]
        l = []
        g = []
        for x2 in xs:
            if x2 < x:
                l.append(x2)
            if x2 >= x:
                g.append(x2)
        if len(l) <= len(g):
            left += sqsort2(l) + [x]
            xxs = g
        else:
            right = [x] + sqsort2(g) + right
            xxs = l


# start_time = time.time_ns()
# # sys.setrecursionlimit(30000)
# l1 = list(reversed(range(15000)))
# # sqsort1(l1)
# print("Total = ",end="")
# print((time.time_ns() - start_time)/ (10 ** 9))

start_time = time.time_ns()
l2 = list(reversed(range(15000)))
sqsort2(l2)
print("Total = ",end="")
print((time.time_ns() - start_time)/ (10 ** 9))