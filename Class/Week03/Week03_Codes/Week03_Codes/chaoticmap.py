x = [0.4012351781]  # key
r = 3.8111010237   # key

for i in range(1, 10000):
    x.append(r * x[i - 1] * (1 - x[i - 1]))  
    # x(n) = r * x(n-1) * (1 - x(n-1))
    print(f"x[{i}] = {x[i]:.16f}")
