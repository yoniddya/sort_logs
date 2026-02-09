# 1
squares = [x*x for x in range(1, 11)]

# 2
words = ["hello", "world", "python", "lambda"]
upper_words = [w.upper() for w in words]

# 3
nums = [3, 12, 7, 24, 5, 18, 31, 40]
even_nums = [n for n in nums if n % 2 == 0]

# 4
names = ["Dan", "Yael", "Ori", "Shir", "Avraham"]
name_lengths = [len(n) for n in names]

# 5
nums = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
odd_squares = [n*n for n in nums if n % 2 == 1]

# 6
words = ["apple", "banana", "cherry", "date"]
word_dict = {w: len(w) for w in words}

# 7
grades = {"Dan": 85, "Yael": 92, "Uri": 78}
reversed_grades = {v: k for k, v in grades.items()}

# 8
prices = {"shirt": 45, "pants": 120, "hat": 30, "shoes": 200, "socks": 15}
filtered_prices = {k: v for k, v in prices.items() if v > 40}

# 9
keys = ["name", "age", "city"]
values = ["Yedidya", 30, "Tel Aviv"]
combined_dict = {k: v for k, v in zip(keys, values)}

# 10
nums = [1, 2, 3, 4, 5, 6, 7, 8]
odd_even = ["even" if n % 2 == 0 else "odd" for n in nums]
